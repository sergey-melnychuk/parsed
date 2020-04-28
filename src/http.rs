use crate::parser::{before, bytes, exact, repeat, single, token, Applicator, MatcherTrait, unit, ParserExt};
use crate::stream::{ByteStream, ToStream};
use std::ops::Add;

pub fn as_string(bytes: Vec<u8>) -> String {
    // Consider changing to: std::str::from_utf8(&[u8]) -> Result<&str>
    // Note: from_utf8 can fail for invalid UTF-8 codes
    // Line below won't fail, but will provide incorrect result
    bytes.into_iter().map(|b| b as char).collect::<String>()
}

#[derive(Debug)]
pub struct Header {
    pub name: String,
    pub value: String,
}

fn header_parser() -> impl MatcherTrait<Header> {
    unit(|| vec![])
        .then(before(':'))
        .map(|(mut vec, val)| {
            vec.push(as_string(val));
            vec
        })
        .then(single(':'))
        .map(|(vec, _)| vec)
        .then(single(' '))
        .map(|(vec, _)| vec)
        .then(before('\r'))
        .map(|(mut vec, val)| {
            vec.push(as_string(val));
            vec
        })
        .then(exact(&[b'\r', b'\n']))
        .map(|(vec, _)| vec)
        .map(|vec| Header {
            name: vec[0].to_owned(),
            value: vec[1].to_owned(),
        })
}

#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub headers: Vec<Header>,
    pub content: Vec<u8>,
}

#[derive(Debug)]
pub struct Response {
    pub protocol: String,
    pub code: u16,
    pub message: String,
    pub headers: Vec<Header>,
    pub content: Vec<u8>,
}

impl Into<String> for Response {
    fn into(self) -> String {
        let headers = self
            .headers
            .into_iter()
            .map(|h| format!("{}: {}", h.name, h.value))
            .collect::<Vec<String>>()
            .join("\r\n");
        let content = as_string(self.content);
        format!("{} {} {}\r\n", self.protocol, self.code, self.message)
            .add(&headers)
            .add("\r\n\r\n")
            .add(&content)
    }
}

fn request_parser() -> impl MatcherTrait<Request> {
    unit(|| Request::default())
        .then(before(' '))
        .save(|req, bytes| req.method = as_string(bytes))
        .then(single(' '))
        .skip()
        .then(before(' '))
        .save(|req, bytes| req.path = as_string(bytes))
        .then(single(' '))
        .skip()
        .then(before('\r'))
        .save(|req, bytes| req.protocol = as_string(bytes))
        .then(exact(&[b'\r', b'\n']))
        .skip()
        .then(repeat(header_parser()))
        .save(|req, vec| req.headers = vec)
        .then(exact(&[b'\r', b'\n']))
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

fn content_parser(len: usize) -> impl MatcherTrait<Vec<u8>> {
    bytes(len)
}

pub fn parse_http_request(stream: &mut ByteStream) -> Option<Request> {
    stream
        .apply(request_parser())
        .map(|r| Some(r))
        .unwrap_or_else(|_| None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_request() {
        let text = "GET / HTTP/1.1\r\nHost: localhost:9000\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n";
        let mut bs = text.to_string().into_stream();
        let req_opt = parse_http_request(&mut bs);
        let req = req_opt.unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert_eq!(req.protocol, "HTTP/1.1");
        assert_eq!(req.headers[0].name, "Host");
        assert_eq!(req.headers[0].value, "localhost:9000");
        assert_eq!(req.headers[1].name, "User-Agent");
        assert_eq!(req.headers[1].value, "curl/7.64.1");
        assert_eq!(req.headers[2].name, "Accept");
        assert_eq!(req.headers[2].value, "*/*");
        assert!(req.content.is_empty());
    }

    #[test]
    fn http_request() {
        let text = "GET /docs/index.html HTTP/1.1\r\nHost: www.nowhere123.com\r\nAccept: image/gif, image/jpeg, */*\r\nAccept-Language: en-us\r\nAccept-Encoding: gzip, deflate\r\nContent-Length: 8\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n\r\n0123456\n";
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
        let text = "GET /chat HTTP/1.1\r\nHost: example.com:8000\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
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
                value: "5".to_string(),
            }],
            content: b"hello".to_vec(),
        };

        let out: String = res.into();
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_string()
        );
    }
}
