use alloc::borrow::ToOwned;
use alloc::sync::Arc;
use alloc::vec;
use core::future::join;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::SeqCst;
use core::time::Duration;

use windows_kernel::asynk::executor:: {spawn};
use windows_kernel::asynk::berk::{TcpListener, TcpSocket, TcpStream};
use windows_kernel::sync::berk::Berk;
use windows_kernel::{println, Error};
use windows_kernel::asynk::executor::naive::{run_future, Yield};
use windows_kernel::asynk::time::{sleep_until, timeout};

// Basic timer primitives
async fn massimpletodavia() -> i32 {
    let inner = Yield { yielded: false };
    inner.await;
    10
}

async fn simple() -> u32 {
    println!("te veo en 1sec");
    sleep_until(Duration::from_secs(1)).await;

    10
}

async fn simple2() -> u32 {
    println!("te veo en 1secs");
    join!(massimpletodavia(), massimpletodavia()).await;

    10
}

async fn simple3() -> u32 {
    println!("te veo en 5secs");
    let s5 = sleep_until(Duration::from_secs(5));
    let s3 = sleep_until(Duration::from_secs(3));
    join!(s5, s3).await;

    10
}

async fn simple4() -> u32 {
    println!("1s");
    let s5 = sleep_until(Duration::from_secs(5));
    let timeout = timeout(s5, Duration::from_secs(1));

    match timeout.await {
        None => 0,
        Some(()) => 10,
    }
}

// Network request/listen

async fn async_listener(
    i: i32,
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
) -> Result<(), Error> {
    if berk_status
        .compare_exchange(false, false, SeqCst, SeqCst)
        .is_ok()
    {
        Err(Error::INSUFFICIENT_RESOURCES)
    } else {
        let _ = spawn(async move {
            let mut listener =
                TcpListener::bind(berk.clone(), berk_status.clone(), "127.0.0.1", "8080").await?;

            /*listener
            .as_stream()
            .for_each_concurrent(1, |socket| async move {
                println!("stream entry");
                if let Ok(socket) = socket {
                    spawn(handle_connection(socket));
                }
            })
            .await;*/

            let mut i = 0;
            loop {
                i += 1;
                match listener.accept().await {
                    Ok(sock) => spawn(handle_connection(sock)),
                    Err(e) => {
                        println!("filed with {:?}", e);
                        break;
                    }
                };
            }

            println!("stream done");

            /*for i in 0..100 {
                println!("enter loop");
                // Asynchronously wait for an inbound socket.

                println!("{i}spawn new conntask");

                let mut socket = match listener.accept().await {
                    Ok(sock) => sock,
                    Err(e) => {
                        println!("failed as {:?}", e);
                        return Err(e);
                    }
                };

            }*/
            //listener.close().await;
            println!("never here");

            Result::<(), Error>::Ok(())
        }).unwrap()
        .await;
        println!("never here?");
        Ok(())
    }
}

async fn handle_connection(mut socket: TcpStream) {
    let mut buf = vec![0; 1024];
    let mut send_buffer = b"GET /uuid HTTP/1.1\r\n\
              Host: httpbin.org\r\n\
              Connection: keep-alive\r\n\
              \r\n"
        .to_owned();

    let n = socket
        .send(send_buffer.as_mut_slice())
        .await
        .unwrap_or_else(|e| {
            println!("send fail {:?}", e);
            0
        });

    let n = socket
        .recv_all(buf.as_mut_slice())
        .await
        .unwrap_or_else(|e| {
            println!("recv fail {:?}", e);
            0
        });
    socket.close().await;
}

pub async fn async_request_executor(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
) -> Result<(), Error> {
    if berk_status
        .compare_exchange(false, false, SeqCst, SeqCst)
        .is_ok()
    {
        Err(Error::INSUFFICIENT_RESOURCES)
    } else {
        for i in 0..10000 {
            spawn(handle_connection(
                TcpSocket::new_v4(berk.clone(), berk_status.clone())
                    .await?
                    .connect("127.0.0.1", "8080")
                    .await?,
            ));
        }
        Ok(())
    }
}

pub async fn async_request(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
) -> Result<(), Error> {
    if berk_status
        .compare_exchange(false, false, SeqCst, SeqCst)
        .is_ok()
    {
        Err(Error::INSUFFICIENT_RESOURCES)
    } else {
        let mut socket = TcpSocket::new_v4(berk.clone(), berk_status.clone())
            .await?
            .connect("127.0.0.1", "8080")
            .await?;

        let mut send_buffer = b"GET /uuid HTTP/1.1\r\n\
              Host: httpbin.org\r\n\
              Connection: keep-alive\r\n\
              \r\n"
            .to_owned();

        for _ in 0..10 {
            let mut recv_buffer = vec![0; 1024];

            socket.send(send_buffer.as_mut_slice()).await?;
            socket.recv_all(recv_buffer.as_mut_slice()).await?;
        }

        socket.close().await;
        Ok(())
    }
}
