use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr as _;

fn auth_user(stream: &mut BufReader<TcpStream>, recv_buf: &mut String, send_buf: &mut String) {
    loop {
        print!("username: ");
        std::io::stdout().flush().unwrap();

        send_buf.clear();
        std::io::stdin().read_line(send_buf).unwrap();
        let Some(name) = send_buf.split_whitespace().next() else {
            continue;
        };
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
                rsa_key.to_string();
            }
            _ => {
                print!("{}", recv_buf);
                continue;
            }
        };

        writeln!(stream.get_mut(), "CHAVE_SIMETRICA 123").expect("Ended connection with server");
        break;
    }
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .and_then(|addr| SocketAddr::from_str(&addr).ok())
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8888)));
    let mut stream = BufReader::new(
        TcpStream::connect(addr).unwrap_or_else(|_| panic!("Cannot connect to address {}", addr)),
    );
    println!("connecting to {addr}");

    let mut send_buf = String::new();
    let mut recv_buf = String::new();
    auth_user(&mut stream, &mut recv_buf, &mut send_buf);
    println!("Registered.");

    {
        // thread de leitura do socket
        let mut stream = BufReader::new(stream.get_ref().try_clone().unwrap());
        std::thread::spawn(move || loop {
            recv_buf.clear();
            stream
                .read_line(&mut recv_buf)
                .expect("Ended connection with server");
            /* decode */
            print!("{}", recv_buf);
        });
    }

    // thread main de leitura do stdin
    send_buf.clear();
    let _ = writeln!(&mut send_buf, "LISTAR_SALAS");
    loop {
        /* encode */
        if send_buf.trim() != "" {
            write!(stream.get_mut(), "{}", send_buf).expect("Ended connection with server");
        }
        send_buf.clear();
        std::io::stdin().read_line(&mut send_buf).unwrap();
    }
}
