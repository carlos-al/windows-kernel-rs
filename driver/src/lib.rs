#![feature(future_join)]
#![no_std]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use core::cell::UnsafeCell;
use core::cmp::Ordering;
use core::sync::atomic::Ordering::{Acquire, Release};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};

use common::*;
use windows_kernel::asynk::executor::WakeRef;
use windows_kernel::asynk::executor::{get_executor, spawn};
use windows_kernel::asynk::executor::naive::{run_future, run_futures};
use windows_kernel::device::{
    Completion, Device, DeviceDoFlags, DeviceFlags, DeviceOperations, DeviceType, RequestError,
};
use windows_kernel::request::IoControlRequest;
use windows_kernel::sync::berk::Berk;
use windows_kernel::sync::thread::{delete_THREAD, Thread};
use windows_kernel::sync::time::Instant;
use windows_kernel::{allocator, kernel_module, println};
use windows_kernel::{Access, Driver, Error, KernelModule, SymbolicLink, __DEVICE};

use crate::async_net::{async_request, async_request_executor};
use crate::sync_net::sync_request;

mod async_net;
mod sync_net;

#[global_allocator]
static ALLOCATOR: allocator::KernelAllocator =
    allocator::KernelAllocator::new(u32::from_ne_bytes(*b"KRNL"));

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}


struct Module {
    _device: Device,
    _symbolic_link: SymbolicLink,
}

impl KernelModule for Module {
    fn init(mut driver: Driver, _registry_path: &str) -> Result<Self, Error> {
        let device = driver.create_device(
            "\\Device\\Example",
            DeviceType::Unknown,
            DeviceFlags::SECURE_OPEN,
            DeviceDoFlags::DO_BUFFERED_IO,
            Access::NonExclusive,
            MyDevice::default(),
        )?;
        let symbolic_link = SymbolicLink::new("\\??\\Example", "\\Device\\Example")?;

        unsafe {
            __DEVICE = Some(device.as_raw_mut());
        }

        Ok(Module {
            _device: device,
            _symbolic_link: symbolic_link,
        })
    }

    fn cleanup(self, _driver: Driver) {
        drop(self._device)
    }
}

kernel_module!(Module);


#[derive(Default)]
struct MyDevice {
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
}

impl MyDevice {
    fn net_init(&mut self, _request: &IoControlRequest) -> Result<u32, Error> {
            // is it already init? 
        if self.berk_status
            .compare_exchange(false, true, SeqCst, SeqCst)   // Overkill, x86 is strongly-ordered already
            .is_ok() // Only  if it was false
        {
            self.berk = Arc::new(Some(Berk::initialize()?));
            self.berk_status.store(true, SeqCst);

            Ok(0)
        }  else {
            Ok(1) //already init
        }
    }

    fn net_destroy(&mut self, _request: &IoControlRequest) -> Result<u32, Error> {
        // is it already deinit?
        if self.berk_status
            .compare_exchange(true, false, SeqCst, SeqCst) 
            .is_ok() // Only  if it was true
        {
            self.berk_status.store(false, SeqCst);

            if let Some(berk) = self.berk.as_ref() {
                berk.wsk.destroy();
            }
            let signal = get_executor().signal();
            let notifier = get_executor().notifier();
            signal.store(true, Release);
            notifier.wake_by_ref();

            self.berk = Arc::new(None);

            Ok(0)
        } else {
            Ok(1) //already deinit
        }
    }

    fn net_async_executor(&mut self, _request: &IoControlRequest) -> Result<u32, Error> {
        let berk = self.berk.clone();
        let berk_status = self.berk_status.clone();

        let _ = spawn(async { //nested spawn to demonstrate we can spawn tasks within a task
            let _ = async_request_executor(berk, berk_status).await;
        });

        Ok(0)
    }

    fn net_sync_request(&mut self, _request: &IoControlRequest) -> Result<u32, Error> {
        if self
            .berk_status
            .compare_exchange(false, false, SeqCst, SeqCst)
            .is_ok()
        {
            Err(Error::INSUFFICIENT_RESOURCES)
        } else {
            for _ in 0..10 {
                let berk = self.berk.clone();
                let berk_status = self.berk_status.clone();
                Thread::spawn(|| match sync_request(berk, berk_status) {
                    Ok(_) => {}
                    Err(_) => {}
                })?;
            }

            Ok(0)
        }
    }
}

impl DeviceOperations for MyDevice {
    fn ioctl(
        &mut self,
        _device: &Device,
        request: IoControlRequest,
    ) -> Result<Completion, RequestError> {
        drop(Thread::current_thread());
        let result = match request.function() {
            (_, IOCTL_KIT_NET_INIT) => self.net_init(&request),
            (_, IOCTL_KIT_NET_DESTROY) => self.net_destroy(&request),
            (_, IOCTL_KIT_NET_NETT) => self.net_async_executor(&request),
            (_, IOCTL_KIT_NET_NETTT) => self.net_sync_request(&request),

            _ => Err(Error::INVALID_PARAMETER),
        };
        unsafe {
            delete_THREAD();
        }
        match result {
            Ok(size) => Ok(Completion::Complete(size, request.into())),
            Err(e) => Err(RequestError(e, request.into())),
        }
    }
}
