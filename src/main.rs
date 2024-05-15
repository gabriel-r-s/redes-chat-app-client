use openssl::{base64, rsa, sha, symm};
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};

type AesKey = [u8; 16];

fn auth_user(stream: &mut BufReader<TcpStream>, recv_buf: &mut String, aes_key: AesKey) {
    loop {
        print!("username: ");
        std::io::stdout().flush().unwrap();

        recv_buf.clear();
        std::io::stdin().read_line(recv_buf).unwrap();
        let Some(name) = recv_buf.split_whitespace().next() else {
            continue;
        };
        let name = name.to_string();
        writeln!(stream.get_mut(), "REGISTRO {}", name).expect("Ended connection with server");

        recv_buf.clear();
        stream
            .read_line(recv_buf)
            .expect("Ended connection with server");
        if recv_buf != "REGISTRO_OK\n" {
            print!("{}", recv_buf);
            continue;
        }

        writeln!(stream.get_mut(), "AUTENTICACAO {}", name).expect("Ended connection with server");
        recv_buf.clear();
        stream
            .read_line(recv_buf)
            .expect("Ended connection with server");
        let mut split = recv_buf.split_whitespace();
        let _rsa_key = match (split.next(), split.next()) {
            (Some("CHAVE_PUBLICA"), Some(rsa_key)) => {
                base64::decode_block(rsa_key).unwrap_or_else(|_| Vec::new())
            }
            _ => {
                print!("{}", recv_buf);
                continue;
            }
        };

        writeln!(
            stream.get_mut(),
            "CHAVE_SIMETRICA {}",
            base64::encode_block(&aes_key),
        )
        .expect("Ended connection with server");
        break;
    }
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .and_then(|addr| SocketAddr::from_str(&addr).ok())
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8888)));
    let mut stream = Box::leak(Box::new(BufReader::new(
        TcpStream::connect(addr).unwrap_or_else(|_| panic!("Cannot connect to address {}", addr)),
    )));
    println!("connecting to {addr}");

    let cipher = symm::Cipher::aes_128_cbc();
    let aes_key: AesKey = rand::random();
    println!("AES key: {}", base64::encode_block(&aes_key));

    let mut send_buf = String::new();
    let mut recv_buf = String::new();
    auth_user(&mut stream, &mut recv_buf, aes_key);
    println!("Registered.");

    {
        // thread de leitura do socket
        std::thread::spawn(move || loop {
            recv_buf.clear();
            stream
                .read_line(&mut recv_buf)
                .expect("Ended connection with server");
            print!("got {recv_buf}");
            /*  let line = symm::decrypt(
             *      cipher,
             *      &aes_key,
             *      None,
             *      &base64::decode_block(buf.trim()).unwrap(),
             *  )
             *  .unwrap();
             *  let line = std::str::from_utf8(&line).unwrap();
             *  println!("{}", line);
             */
        });
    }

    // thread main de leitura do stdin
    send_buf.clear();
    let _ = writeln!(&mut send_buf, "LISTAR_SALAS");
    loop {
        /* encode */
        if send_buf.trim() != "" {
            /*  let line = base64::encode_block(
             *      &symm::encrypt(cipher, &aes_key, None, send_buf.trim().as_bytes()).unwrap(),
             *  );
             */
            println!("sending {:?}", send_buf);
            writeln!(stream.get_mut(), "{}", send_buf).expect("Ended connection with server");
        }
        send_buf.clear();
        std::io::stdin().read_line(&mut send_buf).unwrap();
    }
}
