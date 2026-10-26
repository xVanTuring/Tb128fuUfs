// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read slots: kSlots requests in flight besides slot 0, for the root windows' reads (the workers and their queue are in
// NativeUfs.cpp). Slot 0 stays the synchronous path of RootCommands.h: the bring-up commands, queries, and the store and log
// writes. Each read slot has a contiguous buffer of its own, its command UPIU, response and PRDT in the first page and up to
// kDataMax of data after it, and uses an even request list entry (2, 4, ...): two 32-byte descriptors share a 64-byte line, and
// a line may belong to one slot only (cleaning a neighbour's line could write a stale OCS over the controller's).
// Completion: the controller's transfer-completion interrupt wakes the waiters, and each waiter also looks at its doorbell bit
// at least every 100 us, so a missing interrupt costs time, not a request. Kernel only; the host harness covers slot 0.
constexpr unsigned kSlots = 8, kSlotPage = 4096, kSlotBytes = kSlotPage + kDataMax;
struct UfsSlot {
  IOBufferMemoryDescriptor *dma = nullptr;
  uint8_t *virt = nullptr;
  uint64_t phys = 0;
  unsigned tag = 0;   // request list entry and task tag
};
UfsSlot gSlots[kSlots];
unsigned gSlotCount;   // slots ready for the workers; 0 keeps every read on slot 0
volatile uint32_t gUfsIrqCount;   // also the waiters' event
bool gUfsIrq;
// UFS host (ufshc@4804000) interrupt: DT SPI 0x164, level high.
constexpr uint32_t kUfsIntid = 32 + 0x164;

static void ufsIrq (void *)
{
  // Only the transfer-completion bit: the UIC completion and the error bits stay for the code that waits on them.
  if (read32 (gHost.hc, 0x20) & 1) write32 (gHost.hc, 0x20, 1);
  gUfsIrqCount = gUfsIrqCount + 1;
  native_ufs_slot_stats[2] = native_ufs_slot_stats[2] + 1;
  thread_wakeup (event_t (&gUfsIrqCount));
}

// After bring-up, before any read is queued. False leaves every read on slot 0.
static bool hostSlotsStart (void)
{
  const uint32_t cap = read32 (gHost.hc, 0x00);
  if (!gHost.ready || (cap & 0x1f) + 1 < 2 * kSlots + 1) {
    native_ufs_slot_stats[7] = 0xff000001;
    return false;
  }
  unsigned ready = 0;
  for (; ready < kSlots; ++ready) {
    UfsSlot &slot = gSlots[ready];
    slot.dma = IOBufferMemoryDescriptor::inTaskWithOptions (
      kernel_task, static_cast<IOOptionBits> (kIODirectionInOut) | static_cast<IOOptionBits> (kIOMemoryPhysicallyContiguous) |
      static_cast<IOOptionBits> (kIOMemoryMapperNone), kSlotBytes, 4096);
    if (!slot.dma) break;
    slot.virt = static_cast<uint8_t *> (slot.dma->getBytesNoCopy ());
    IOByteCount contiguous = 0;
    slot.phys = slot.dma->getPhysicalSegment (0, &contiguous, kIOMemoryMapperNone);
    if (!slot.virt || !slot.phys || (slot.phys & 4095) || contiguous < kSlotBytes ||
        (!(cap & 0x01000000) && slot.phys + kSlotBytes > 0x100000000ULL)) {
      slot.dma->release ();
      slot = UfsSlot ();
      break;
    }
    slot.tag = 2 + 2 * ready;
    bzero (slot.virt, kSlotBytes);
    cacheCivac (slot.virt, kSlotBytes);
  }
  uint64_t state = ready;
  if (ready && armcpu_spi_attach) {
    uint32_t readback = 0;
    uint64_t router = 0;
    const IOReturn attached = armcpu_spi_attach (kUfsIntid, false, ufsIrq, nullptr, &readback, &router);
    state |= uint64_t (attached & 0xff) << 16;
    if (attached == kIOReturnSuccess) {
      gUfsIrq = true;
      hostWrite (0x20, 1);
      hostWrite (0x24, 1);   // UTRCE only
      state |= 1U << 8;
    }
  }
  native_ufs_slot_stats[7] = state | (uint64_t (read32 (gHost.hc, 0x4c)) << 32);   // and UTRIACR as found
  gSlotCount = ready;
  return ready != 0;
}

// Read `blocks` 4096-byte blocks of LUN 0 from `lba` into slot.virt + kSlotPage.
static IOReturn hostSlotRead (UfsSlot &slot, uint64_t lba, uint32_t blocks)
{
  if (!blocks || blocks > kDataMax / 4096 || lba > 0xffffffffULL - (blocks - 1)) return kIOReturnBadArgument;
  if (!gHost.ready || gHost.poisoned) return kIOReturnNotReady;
  const uint32_t bit = 1U << slot.tag, bytes = blocks * 4096U;
  if (read32 (gHost.hc, 0x58) & bit) {
    gHost.poisoned = true;
    gHost.ready = false;
    return recordTransport (kIOReturnBusy, 15);
  }
  if (read32 (gHost.hc, 0x20) & kUfsFatalStatus) {
    gHost.poisoned = true;
    gHost.ready = false;
    return recordTransport (kIOReturnIOError, 15);
  }
  uint8_t *ucd = slot.virt;
  memset (ucd, 0, 64);
  ucd[0] = 0x01;                     // COMMAND UPIU
  ucd[1] = 0x40;                     // data in
  ucd[3] = uint8_t (slot.tag);
  putBe32 (ucd + 12, bytes);
  const uint8_t cdb[10] = { 0x28, 0, uint8_t (lba >> 24), uint8_t (lba >> 16), uint8_t (lba >> 8), uint8_t (lba), 0,
                            uint8_t (blocks >> 8), uint8_t (blocks), 0 };
  memcpy (ucd + 16, cdb, sizeof (cdb));
  const uint64_t dataPhys = slot.phys + kSlotPage;
  uint32_t *prd = reinterpret_cast<uint32_t *> (ucd + kPrdtOffset);
  prd[0] = static_cast<uint32_t> (dataPhys);
  prd[1] = static_cast<uint32_t> (dataPhys >> 32);
  prd[2] = 0;
  prd[3] = bytes - 1;
  uint32_t *words = reinterpret_cast<uint32_t *> (gHost.virt + 32 * slot.tag);
  words[0] = 0x10000000U | (2U << 25) | (1U << 24);   // UFS storage command, data to the host, completion interrupt
  words[1] = 0;
  words[2] = 0x0fU;
  words[3] = 0;
  words[4] = static_cast<uint32_t> (slot.phys);
  words[5] = static_cast<uint32_t> (slot.phys >> 32);
  words[6] = (512U >> 2) | ((kRspOffset >> 2) << 16);
  words[7] = 1U | ((kPrdtOffset >> 2) << 16);
  // The descriptor's line, the command UPIU's and the PRDT entry's. The CPU never writes the response or the data, so they hold
  // no dirty line; what is prefetched while the controller writes them is dropped after it.
  cacheCivac (words, 64);
  cacheCivac (ucd, 64);
  cacheCivac (ucd + kPrdtOffset, 64);
  const uint64_t inFlight = __atomic_add_fetch (&native_ufs_slot_stats[6], 1, __ATOMIC_RELAXED);
  if (inFlight > native_ufs_slot_stats[5]) native_ufs_slot_stats[5] = inFlight;
  const uint64_t began = mach_absolute_time ();
  uint64_t deadline;
  clock_interval_to_deadline (1000000, kMicrosecondScale, &deadline);
  hostWrite (0x58, bit);
  IOReturn result = kIOReturnSuccess;
  uint32_t ocs = 15;
  for (;;) {
    // Waiting first, then looking, so an interrupt between the look and the sleep is not missed.
    assert_wait_timeout (event_t (&gUfsIrqCount), THREAD_UNINT, gUfsIrq ? 100 : 20, NSEC_PER_USEC);
    if (read32 (gHost.hc, 0x20) & kUfsFatalStatus) {
      clear_wait (current_thread (), THREAD_AWAKENED);
      result = kIOReturnIOError;
      break;
    }
    if (!(read32 (gHost.hc, 0x58) & bit)) {
      cacheInvalidate (words, 64);
      ocs = words[2] & 0xff;
      if (ocs != 15) {
        clear_wait (current_thread (), THREAD_AWAKENED);
        break;
      }
    }
    if (mach_absolute_time () >= deadline) {
      clear_wait (current_thread (), THREAD_AWAKENED);
      result = kIOReturnTimeout;
      break;
    }
    thread_block (THREAD_CONTINUE_NULL);
    __atomic_fetch_add (&native_ufs_slot_stats[3], 1, __ATOMIC_RELAXED);
  }
  __atomic_fetch_sub (&native_ufs_slot_stats[6], 1, __ATOMIC_RELAXED);
  uint64_t us = 0;
  absolutetime_to_nanoseconds (mach_absolute_time () - began, &us);
  us /= 1000;
  if (us > native_ufs_slot_stats[4]) native_ufs_slot_stats[4] = us;
  __atomic_fetch_add (&native_ufs_slot_stats[0], 1, __ATOMIC_RELAXED);
  if (result != kIOReturnSuccess) {
    // As slot 0: no cancel or retry; the controller may still own the buffers.
    __atomic_fetch_add (&native_ufs_slot_stats[1], 1, __ATOMIC_RELAXED);
    gHost.poisoned = true;
    gHost.ready = false;
    return recordTransport (result, ocs);
  }
  cacheInvalidate (ucd + kRspOffset, 128);
  const uint8_t *rsp = ucd + kRspOffset;
  if (ocs) {
    __atomic_fetch_add (&native_ufs_slot_stats[1], 1, __ATOMIC_RELAXED);
    return recordTransport (kIOReturnIOError, ocs);
  }
  // The checks of hostResponseHeader and hostScsiDir, on this slot's response.
  if (rsp[0] != 0x21) return hostProtocolError (1);
  if (rsp[3] != slot.tag) return hostProtocolError (2);
  if (rsp[2] != 0) return hostProtocolError (3);
  const unsigned length = (unsigned (rsp[10]) << 8) | rsp[11];
  if (rsp[8] || length > 512 - 32) return hostProtocolError (4);
  const uint32_t scsi = (uint32_t (rsp[6]) << 8) | rsp[7], residual = loadBe32 (rsp + 12);
  if (!scsi && ((rsp[1] & 0x60) || residual)) return hostProtocolError (6);
  if (scsi) {
    __atomic_fetch_add (&native_ufs_slot_stats[1], 1, __ATOMIC_RELAXED);
    gRootDiagnostic.scsi = scsi;
    return kIOReturnNotReady;
  }
  cacheInvalidate (slot.virt + kSlotPage, bytes);
  return kIOReturnSuccess;
}
