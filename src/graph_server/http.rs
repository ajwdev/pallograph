// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Just enough HTTP/1.1 to answer GET requests from a browser on one
//! connection, then close it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::page::Response;

/// Requests longer than this are refused, so a stray client can't make the
/// server buffer without bound.
const MAX_LINE: usize = 8 * 1024;

/// Reads one request from `stream`, answers it with `handler(target)` for a
/// GET, and closes the connection.
pub fn serve_connection(stream: TcpStream, handler: &dyn Fn(&str) -> Response) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(&stream);
    let response = match read_request_line(&mut reader) {
        Ok(line) => respond(&line, handler),
        Err(status) => plain(status, "bad request"),
    };
    let mut stream = &stream;
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
}

/// The request line, after skipping the headers that follow it.
fn read_request_line(reader: &mut impl BufRead) -> Result<String, u16> {
    let request_line = read_line(reader)?;
    loop {
        let header = read_line(reader)?;
        if header.is_empty() {
            return Ok(request_line);
        }
    }
}

fn read_line(reader: &mut impl BufRead) -> Result<String, u16> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(MAX_LINE as u64)
        .read_until(b'\n', &mut line)
        .map_err(|_| 400u16)?;
    if read == 0 || !line.ends_with(b"\n") {
        return Err(400);
    }
    Ok(String::from_utf8_lossy(&line).trim_end().to_string())
}

fn respond(request_line: &str, handler: &dyn Fn(&str) -> Response) -> Response {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return plain(400, "bad request");
    };
    if method != "GET" {
        return plain(405, "only GET is supported");
    }
    if !target.starts_with('/') {
        return plain(400, "bad request target");
    }
    handler(target)
}

fn plain(status: u16, message: &str) -> Response {
    Response {
        status,
        content_type: "text/plain; charset=utf-8",
        body: format!("{message}\n"),
    }
}
