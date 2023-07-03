//! Minimal support for uart_16550 serial I/O.
//!
//! # Usage
//!
//! ```no_run
//! use uart_16550::SerialPort;
//!
//! const SERIAL_IO_PORT: u16 = 0x3F8;
//!
//! let mut serial_port = unsafe { SerialPort::new(SERIAL_IO_PORT) };
//! serial_port.init();
//!
//! // Now the serial port is ready to be used. To send a byte:
//! serial_port.send(42);
//!
//! // To receive a byte:
//! let data = serial_port.receive();
//! ```

#![no_std]
#![warn(missing_docs)]

use bitflags::bitflags;
use core::fmt;
use x86_64::instructions::port::{Port, PortReadOnly, PortWriteOnly};

macro_rules! wait_for {
    ($cond:expr) => {
        while !$cond {
            core::hint::spin_loop()
        }
    };
}

bitflags! {
    /// Interrupt enable flags
    struct IntEnFlags: u8 {
        const RECEIVED = 1;
        const SENT = 1 << 1;
        const ERRORED = 1 << 2;
        const STATUS_CHANGE = 1 << 3;
        // 4 to 7 are unused
    }
}

bitflags! {
    /// Line status flags
    struct LineStsFlags: u8 {
        const INPUT_FULL = 1;
        // 1 to 4 unknown
        const OUTPUT_EMPTY = 1 << 5;
        // 6 and 7 unknown
    }
}

/// An interface to a serial port that allows sending out individual bytes.
pub struct SerialPort {
    data: Port<u8>,
    int_en: PortWriteOnly<u8>,
    fifo_ctrl: PortWriteOnly<u8>,
    line_ctrl: PortWriteOnly<u8>,
    modem_ctrl: PortWriteOnly<u8>,
    line_sts: PortReadOnly<u8>,
}

struct BaudRateDivisor {
    least: u8,
    most: u8,
}

/// Serial port baud rates.
///
/// ## Portability
///
/// The `BaudRate` variants with numeric suffixes, e.g., `Baud9600`, indicate standard baud rates
/// that are widely-supported on many systems. While non-standard baud rates can be set with
/// `BaudOther`, their behavior is system-dependent. Some systems may not support arbitrary baud
/// rates. Using the standard baud rates is more likely to result in portable applications.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BaudRate {
    /// 110 baud.
    Baud110,
    /// 300 baud.
    Baud300,
    /// 600 baud.
    Baud600,
    /// 1200 baud.
    Baud1200,
    /// 2400 baud.
    Baud2400,
    /// 4800 baud.
    Baud4800,
    /// 9600 baud.
    Baud9600,
    /// 19,200 baud.
    Baud19200,
    /// 38,400 baud.
    Baud38400,
    /// 57,600 baud.
    Baud57600,
    /// 115,200 baud.
    Baud115200,
    /// Non-standard baud rates.
    ///
    /// `BaudOther` can be used to set non-standard baud rates by setting its member to be the
    /// desired baud rate.
    ///
    /// ```no_run
    /// uart_16440::BaudRate::BaudOther(4_000_000); // 4,000,000 baud
    /// ```
    ///
    /// Non-standard baud rates may not be supported on all systems.
    BaudOther(usize),
}

impl BaudRate {
    const UART_CLOCK_FACTOR: usize = 16;
    const OSC_FREQ: usize = 1843200;

    /// Creates a `BaudRate` for a particular speed.
    ///
    /// This function can be used to select a `BaudRate` variant from an integer containing the
    /// desired baud rate.
    ///
    /// ## Example
    ///
    /// ```
    /// # use serial_core::BaudRate;
    /// assert_eq!(BaudRate::Baud9600, BaudRate::from_speed(9600));
    /// assert_eq!(BaudRate::Baud115200, BaudRate::from_speed(115200));
    /// assert_eq!(BaudRate::BaudOther(4000000), BaudRate::from_speed(4000000));
    /// ```
    pub fn from_speed(speed: usize) -> BaudRate {
        match speed {
            110 => BaudRate::Baud110,
            300 => BaudRate::Baud300,
            600 => BaudRate::Baud600,
            1200 => BaudRate::Baud1200,
            2400 => BaudRate::Baud2400,
            4800 => BaudRate::Baud4800,
            9600 => BaudRate::Baud9600,
            19200 => BaudRate::Baud19200,
            38400 => BaudRate::Baud38400,
            57600 => BaudRate::Baud57600,
            115200 => BaudRate::Baud115200,
            n => BaudRate::BaudOther(n),
        }
    }

    /// Returns the baud rate as an integer.
    ///
    /// ## Example
    ///
    /// ```
    /// # use serial_core::BaudRate;
    /// assert_eq!(9600, BaudRate::Baud9600.speed());
    /// assert_eq!(115200, BaudRate::Baud115200.speed());
    /// assert_eq!(4000000, BaudRate::BaudOther(4000000).speed());
    /// ```
    pub fn speed(&self) -> usize {
        match *self {
            BaudRate::Baud110 => 110,
            BaudRate::Baud300 => 300,
            BaudRate::Baud600 => 600,
            BaudRate::Baud1200 => 1200,
            BaudRate::Baud2400 => 2400,
            BaudRate::Baud4800 => 4800,
            BaudRate::Baud9600 => 9600,
            BaudRate::Baud19200 => 19200,
            BaudRate::Baud38400 => 38400,
            BaudRate::Baud57600 => 57600,
            BaudRate::Baud115200 => 115200,
            BaudRate::BaudOther(n) => n,
        }
    }

    fn uart_divisor(&self) -> BaudRateDivisor {
        let divisor =
            (BaudRate::OSC_FREQ / (self.speed() as usize * BaudRate::UART_CLOCK_FACTOR)) as u16;
        BaudRateDivisor {
            least: (divisor & 0xff) as u8,
            most: (divisor >> 8) as u8,
        }
    }
}

impl SerialPort {
    /// Creates a new serial port interface on the given I/O port.
    ///
    /// This function is unsafe because the caller must ensure that the given base address
    /// really points to a serial port device.
    pub const unsafe fn new(base: u16) -> SerialPort {
        SerialPort {
            data: Port::new(base),
            int_en: PortWriteOnly::new(base + 1),
            fifo_ctrl: PortWriteOnly::new(base + 2),
            line_ctrl: PortWriteOnly::new(base + 3),
            modem_ctrl: PortWriteOnly::new(base + 4),
            line_sts: PortReadOnly::new(base + 5),
        }
    }

    /// Initializes the serial port.
    ///
    /// The default configuration of [38400/8-N-1](https://en.wikipedia.org/wiki/8-N-1) is used.
    pub fn init(&mut self, baud_rate: BaudRate) {
        unsafe {
            // Disable interrupts
            self.int_en.write(0x00);

            // Enable DLAB
            self.line_ctrl.write(0x80);

            // Set maximum speed according the input baud rate by configuring DLL and DLM
            let divisor = baud_rate.uart_divisor();
            self.data.write(divisor.least);
            self.int_en.write(divisor.most);

            // Disable DLAB and set data word length to 8 bits
            self.line_ctrl.write(0x03);

            // Enable FIFO, clear TX/RX queues and
            // set interrupt watermark at 14 bytes
            self.fifo_ctrl.write(0xC7);

            // Mark data terminal ready, signal request to send
            // and enable auxilliary output #2 (used as interrupt line for CPU)
            self.modem_ctrl.write(0x0B);

            // Enable interrupts
            self.int_en.write(0x01);
        }
    }

    fn line_sts(&mut self) -> LineStsFlags {
        unsafe { LineStsFlags::from_bits_truncate(self.line_sts.read()) }
    }

    /// Sends a byte on the serial port.
    pub fn send(&mut self, data: u8) {
        unsafe {
            match data {
                8 | 0x7F => {
                    wait_for!(self.line_sts().contains(LineStsFlags::OUTPUT_EMPTY));
                    self.data.write(8);
                    wait_for!(self.line_sts().contains(LineStsFlags::OUTPUT_EMPTY));
                    self.data.write(b' ');
                    wait_for!(self.line_sts().contains(LineStsFlags::OUTPUT_EMPTY));
                    self.data.write(8)
                }
                _ => {
                    wait_for!(self.line_sts().contains(LineStsFlags::OUTPUT_EMPTY));
                    self.data.write(data);
                }
            }
        }
    }

    /// Receives a byte on the serial port.
    pub fn receive(&mut self) -> u8 {
        unsafe {
            wait_for!(self.line_sts().contains(LineStsFlags::INPUT_FULL));
            self.data.read()
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}
