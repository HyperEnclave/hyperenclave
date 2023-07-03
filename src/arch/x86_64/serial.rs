// Copyright (C) 2023 Ant Group CO., Ltd. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::fmt::{Arguments, Result, Write};

use spin::Mutex;
use uart_16550::{BaudRate, SerialPort};

const SERIAL_IO_PORT: u16 = 0x3F8;

struct ByteConvertor<T: Write> {
    inner: T,
}

impl<T: Write> ByteConvertor<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: Write> Write for ByteConvertor<T> {
    fn write_str(&mut self, s: &str) -> Result {
        for byte in s.bytes() {
            match byte {
                b'\n' => {
                    self.inner.write_char('\r')?;
                    self.inner.write_char('\n')?;
                }
                _ => self.inner.write_char(byte as char)?,
            }
        }
        Ok(())
    }
}

lazy_static! {
    static ref SERIAL1: Mutex<ByteConvertor<SerialPort>> = {
        let mut serial_port = unsafe { SerialPort::new(SERIAL_IO_PORT) };
        serial_port.init(BaudRate::Baud115200);
        Mutex::new(ByteConvertor::new(serial_port))
    };
}

pub fn putfmt(fmt: Arguments) {
    SERIAL1
        .lock()
        .write_fmt(fmt)
        .expect("Printing to serial failed");
}
