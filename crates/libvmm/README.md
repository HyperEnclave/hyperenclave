# Library VMM

Experimenting with building library VMM in Rust. Unclear what this will turn out to be.

## License

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)


## New to Rust?!
 - [Here](https://www.rust-lang.org/tools/install) you can find out how to install Rust on your system.
 - [This](https://www.rust-lang.org/learn) is a very clear point to start off learning Rust or to find more details about it.


## Installing project dependencies 
```
$ ./scripts/install-deps
```

- Logout and login again to make group modifications to be effective.

## How to run the unit tests
```
$ cd src/testing
$ make
```


## Todo

- [x] Basic VMCS handling support.
- [x] Add a first unit test.
- [x] Add basic EPT page table handling.
- [x] Add support for managing MSR and IO bitmaps.
- [x] Add support for skipping instructions.
- [x] VMLaunch/VMResume support.
- [x] Add basic VMCS validation code.
- [ ] Port kvm-unit-tests tests.
- [ ] Port KVM kernel selftests.
- [ ] Add NMI support.
- [ ] Add support for SGX virtualization.
- [ ] Add processor craziness mitigations for speculation attacks.
- [ ] Add MCE handling.
- [ ] Add support for VPID.
- [ ] MONITOR & MWAIT + APERF/MPERF emulation.
- [ ] Add CPUID emulation.
- [ ] Add PLE support.
- [ ] Add TSC scaling support.
- [ ] Add VMCS shadowing support.
- [ ] Add preemption timer support.
- [ ] Add PML support.
- [ ] Instruction emulation.
- [ ] Create a library OS to use it for testing.
- [ ] Add support for request-interrupt-window.
- [ ] Add support for Interrupt on entry settings.
- [ ] Add support for managing IOMMU page tables.
- [ ] Add support for hardware posted interrupt.
- [ ] Add support for APICv.
- [ ] Add support for SVM.
- [ ] Add better support for non-root guest mode code.
- [ ] Extend the VMCS validation checks in (${}/src/x86_64/instructions/vmcs.rs).
  - [ ] 26.2 VMX controls and host state.
    - [ ] 26.2.1 VMX controls.
      - [ ] 26.2.1.2 VM Exit control validation.
      - [ ] 26.2.1.3 VM Entry control validation.
    - [ ] 26.2.2 Host controls and MSRs.
    - [ ] 26.2.3 Host segment and descriptor tables.
    - [ ] 26.2.4 Address space size.
  - [ ] 26.3 Guest state.
