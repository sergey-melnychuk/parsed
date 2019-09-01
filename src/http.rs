use crate::parser::{before, bytes, exact, repeat, single, token, Applicator, Parser};
use crate::stream::{ByteStream, ToStream};
use std::ops::Add;

fn as_string(bytes: Vec<u8>) -> String {
    bytes.into_iter().map(|b| b as char).collect()
}

#[derive(Debug)]
struct Header {
    name: String,
    value: String,
}

fn header_parser() -> Parser<Header> {
    Parser::init(|| vec![])
        .then(before(':'))
        .map(|(mut vec, val)| {
            vec.push(as_string(val));
            vec
        })
        .then(single(':'))
        .map(|(vec, _)| vec)
        .then(single(' '))
        .map(|(vec, _)| vec)
        .then(before('\n'))
        .map(|(mut vec, val)| {
            vec.push(as_string(val));
            vec
        })
        .then(single('\n'))
        .map(|(vec, _)| vec)
        .map(|vec| Header {
            name: vec[0].to_owned(),
            value: vec[1].to_owned(),
        })
}

#[derive(Debug, Default)]
struct Request {
    method: String,
    path: String,
    protocol: String,
    headers: Vec<Header>,
    content: Vec<u8>,
}

#[derive(Debug)]
struct Response {
    protocol: String,
    code: u16,
    message: String,
    headers: Vec<Header>,
    content: Vec<u8>,
}

impl Into<String> for Response {
    fn into(self) -> String {
        let headers = self
            .headers
            .into_iter()
            .map(|h| format!("{}: {}", h.name, h.value))
            .collect::<Vec<String>>()
            .join("\n");
        let content = as_string(self.content);
        format!("{} {} {}\n", self.protocol, self.code, self.message)
            .add(&headers)
            .add("\n\n")
            .add(&content)
    }
}

fn request_parser() -> Parser<Request> {
    Parser::init(|| Request::default())
        .then(before(' '))
        .save(|req, bytes| req.method = as_string(bytes))
        .then(single(' '))
        .skip()
        .then(before(' '))
        .save(|req, bytes| req.path = as_string(bytes))
        .then(single(' '))
        .skip()
        .then(before('\n'))
        .save(|req, bytes| req.protocol = as_string(bytes))
        .then(single('\n'))
        .skip()
        .then(repeat(header_parser().into()))
        .save(|req, vec| req.headers = vec)
        .then(single('\n'))
        .skip()
        .then_with(|req| {
            let n: usize = get_content_length(req).unwrap_or(0);
            bytes(n)
        })
        .save(|req, content| req.content = content)
}

fn get_header_value(req: &Request, name: String) -> Option<String> {
    req.headers
        .iter()
        .find(|h| h.name == name)
        .map(|h| h.value.clone())
}

fn get_content_length(req: &Request) -> Option<usize> {
    get_header_value(req, "Content-Length".to_string())
        .map(|len| len.parse::<usize>().unwrap_or(0))
}

fn content_parser(len: usize) -> Parser<Vec<u8>> {
    Parser::unit(bytes(len))
}

fn parse_http_request(stream: &mut ByteStream) -> Option<Request> {
    stream
        .apply(request_parser())
        .map(|r| Some(r))
        .unwrap_or_else(|_| None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request() {
        let text = r#"GET /docs/index.html HTTP/1.1
Host: www.nowhere123.com
Accept: image/gif, image/jpeg, */*
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Content-Length: 8
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)

0123456
"#;
        let mut bs = text.to_string().into_stream();
        let req_opt = parse_http_request(&mut bs);
        let req = req_opt.unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/docs/index.html");
        assert_eq!(req.protocol, "HTTP/1.1");
        assert_eq!(req.content, b"0123456\n");
        assert_eq!(req.headers[0].name, "Host");
        assert_eq!(req.headers[0].value, "www.nowhere123.com");
        assert_eq!(req.headers[1].name, "Accept");
        assert_eq!(req.headers[1].value, "image/gif, image/jpeg, */*");
        assert_eq!(req.headers[2].name, "Accept-Language");
        assert_eq!(req.headers[2].value, "en-us");
        assert_eq!(req.headers[3].name, "Accept-Encoding");
        assert_eq!(req.headers[3].value, "gzip, deflate");
        assert_eq!(req.headers[4].name, "Content-Length");
        assert_eq!(req.headers[4].value, "8");
        assert_eq!(req.headers[5].name, "User-Agent");
        assert_eq!(
            req.headers[5].value,
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
        );
    }

    #[test]
    fn http_upgrade() {
        let text = r#"GET /chat HTTP/1.1
Host: example.com:8000
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

"#;
        let mut bs = text.to_string().into_stream();
        let req_opt = bs.apply(request_parser());
        let req = req_opt.unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/chat");
        assert_eq!(req.protocol, "HTTP/1.1");
        assert!(req.content.is_empty());
        assert_eq!(req.headers[0].name, "Host");
        assert_eq!(req.headers[0].value, "example.com:8000");
        assert_eq!(req.headers[1].name, "Upgrade");
        assert_eq!(req.headers[1].value, "websocket");
        assert_eq!(req.headers[2].name, "Connection");
        assert_eq!(req.headers[2].value, "Upgrade");
        assert_eq!(req.headers[3].name, "Sec-WebSocket-Key");
        assert_eq!(req.headers[3].value, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(req.headers[4].name, "Sec-WebSocket-Version");
        assert_eq!(req.headers[4].value, "13");
    }

    #[test]
    fn http_response() {
        let res = Response {
            protocol: "HTTP/1.1".to_string(),
            code: 200,
            message: "OK".to_string(),
            headers: vec![Header {
                name: "Content-Length".to_string(),
                value: "6".to_string(),
            }],
            content: b"hello\n".to_vec(),
        };

        let out: String = res.into();
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\nContent-Length: 6\n\nhello\n".to_string()
        );
    }
}
