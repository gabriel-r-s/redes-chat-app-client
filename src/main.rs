#![feature(str_split_whitespace_remainder)]
use openssl::{base64, rsa, sha, symm};
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr as _;

type AesKey = [u8; 32];

fn auth_user(
    stream: &mut BufReader<TcpStream>,
    recv_buf: &mut String,
    send_buf: &mut String,
    aes_key: AesKey,
) {
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
        // while recv_buf.trim() == "" {
        stream
            .read_line(recv_buf)
            .expect("Ended connection with server");
        // }
        if recv_buf.trim() != "REGISTRO_OK" {
            print!("{}", recv_buf);
            continue;
        }

        writeln!(stream.get_mut(), "AUTENTICACAO {}", name).expect("Ended connection with server");
        recv_buf.clear();
        // while recv_buf.trim() == "" {
        stream
            .read_line(recv_buf)
            .expect("Ended connection with server");
        // }
        let mut split = recv_buf.split_whitespace();
        let rsa_key = match (split.next(), split.next()) {
            (Some("CHAVE_PUBLICA"), Some(rsa_key)) => {
                let rsa_key =
                    base64::decode_block(rsa_key).expect("Falha ao decodificar chave pública");
                rsa::Rsa::public_key_from_der(&rsa_key).expect("Falha ao decodificar chave pública")
            }
            _ => {
                print!("{}", recv_buf);
                continue;
            }
        };
        let mut enc_aes_key = vec![0; rsa_key.size() as usize];
        rsa_key
            .public_encrypt(&aes_key, &mut enc_aes_key, rsa::Padding::PKCS1)
            .expect("Falha ao encriptar chave simétrica");
        let enc_aes_key = base64::encode_block(&enc_aes_key);

        writeln!(stream.get_mut(), "CHAVE_SIMETRICA {}", enc_aes_key)
            .expect("Ended connection with server");
        break;
    }
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .and_then(|addr| SocketAddr::from_str(&addr).ok())
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8080)));
    let mut stream = BufReader::new(
        TcpStream::connect(addr).unwrap_or_else(|_| panic!("Cannot connect to address {}", addr)),
    );
    println!("connecting to {addr}");

    let cipher = symm::Cipher::aes_256_ecb();
    let aes_key: AesKey = rand::random();
    println!("AES key: {:?}", aes_key);

    let mut send_buf = String::new();
    let mut recv_buf = String::new();
    auth_user(&mut stream, &mut recv_buf, &mut send_buf, aes_key);
    println!("Registered.");

    {
        // thread de leitura do socket
        let mut stream = BufReader::new(stream.get_ref().try_clone().unwrap());
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            recv_buf.clear();
            stream
                .read_line(&mut recv_buf)
                .expect("Ended connection with server");
            let buf_trim = recv_buf.trim();
            if buf_trim == "" {
                continue;
            }
            let Ok(line) = base64::decode_block(buf_trim) else {
                println!("erro de decodificação base64");
                continue;
            };
            let Ok(line) = symm::decrypt(cipher, &aes_key, None, &line) else {
                println!("erro de decodificação aes");
                continue;
            };
            let Ok(line) = std::str::from_utf8(&line) else {
                println!("erro de decodificação utf8");
                continue;
            };
            println!("{}", line);
        });
    }

    // thread main de leitura do stdin
    send_buf.clear();
    let _ = write!(&mut send_buf, "LISTAR_SALAS");
    loop {
        if let Some(hashed) = hash_pass(&send_buf) {
            send_buf = hashed;
        }
        let buf_trim = send_buf.trim();
        if buf_trim != "" {
            let line = base64::encode_block(
                &symm::encrypt(cipher, &aes_key, None, buf_trim.as_bytes()).unwrap(),
            );
            writeln!(stream.get_mut(), "{}", line).expect("Ended connection with server");
        }
        send_buf.clear();
        std::io::stdin().read_line(&mut send_buf).unwrap();
    }
}

fn hash_pass(buf: &str) -> Option<String> {
    let mut split = buf.split_whitespace();
    match (split.next(), split.next()) {
        (Some("CRIAR_SALA"), Some(access @ ("PUBLICA" | "PRIVADA"))) => {
            let name = split.next()?;
            let pass = split.remainder()?.trim();
            if pass == "" {
                return None;
            }
            let mut hasher = sha::Sha256::new();
            hasher.update(pass.as_bytes());
            let hash = hasher.finish();
            let hash = base64::encode_block(&hash);
            Some(format!("CRIAR_SALA {} {} {}", access, name, hash))
        }
        (Some("ENTRAR_SALA"), Some(name)) => {
            let pass = split.remainder()?.trim();
            if pass == "" {
                return None;
            }
            let mut hasher = sha::Sha256::new();
            hasher.update(pass.as_bytes());
            let hash = hasher.finish();
            let hash = base64::encode_block(&hash);
            Some(format!("ENTRAR_SALA {} {}", name, hash))
        }
        _ => None,
    }
}
