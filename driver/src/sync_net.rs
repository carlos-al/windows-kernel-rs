use alloc::borrow::ToOwned;
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::SeqCst;

use windows_kernel::sync::berk::Berk;
use windows_kernel::{sync, Error};

pub fn sync_request(berk: Arc<Option<Berk>>, berk_status: Arc<AtomicBool>) -> Result<(), Error> {
    if berk_status
        .compare_exchange(false, false, SeqCst, SeqCst)
        .is_ok()
    {
        Err(Error::INSUFFICIENT_RESOURCES)
    } else {
        let mut socket = sync::berk::TcpSocket::new_v4(berk.clone(), berk_status.clone())?
            .connect("127.0.0.1", "8080")?;

        let mut send_buffer = b"GET /uuid HTTP/1.1\r\n\
              Host: httpbin.org\r\n\
              Connection: keep-alive\r\n\
              \r\n"
            .to_owned();

        for _ in 0..10 {
            let mut recv_buffer = vec![0; 1024];

            socket.send(send_buffer.as_mut_slice())?;
            socket.recv_all(recv_buffer.as_mut_slice())?;
        }

        Ok(())
    }
}
