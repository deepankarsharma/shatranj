#![feature(stdarch_x86_avx512)]

use std::fs::File;
use std::io::{Error, Read, self, BufRead, BufReader};
use std::os::unix::fs::OpenOptionsExt;
use memmap2::{Advice, Mmap};
use std::process::Command;
use std::os::unix::io::AsRawFd;
use io_uring::{opcode, types, IoUring};
use libc::iovec;
use std::arch::x86_64::*;
use std::fmt;

const BUFFER_SIZE: usize = 65536;
const NUM_BUFFERS: usize = 64;
pub fn get_filename() -> String {
    std::env::var("IO_BENCH_DATA_FILE").unwrap()
}

fn print_m256i(value: __m256i) {
    let mut bytes = [0u8; 32];
    unsafe {
        std::arch::x86_64::_mm256_storeu_si256(bytes.as_mut_ptr() as *mut _, value);
    }

    print!("[");
    for i in 0..32 {
        print!("{:#04x}", bytes[i]);
        if i < 31 {
            print!(", ");
        }
    }
    println!("]");
}

fn reset_file_caches() {
    // Execute the command to reset file caches
    let output = Command::new("sudo")
        .arg("sh")
        .arg("-c")
        .arg("echo 3 > /proc/sys/vm/drop_caches")
        .output()
        .expect("Failed to reset file caches");

    // Check if the command executed successfully
    if !output.status.success() {
        panic!("Failed to reset file caches: {:?}", output);
    }
}

pub fn count_newlines_standard(filename: &str) -> Result<usize, std::io::Error> {
    let file = File::open(filename)?;
    let reader = BufReader::with_capacity(16 * 1024, file);

    let newline_count = reader.lines().count();

    reset_file_caches();
    Ok(newline_count)
}


pub fn count_newlines_standard_non_appending(filename: &str) -> Result<usize, std::io::Error> {
    let file = File::open(filename)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut newline_count = 0;

    loop {
        let len = {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                break;
            }
            newline_count += buffer.iter().filter(|&&b| b == b'\n').count();
            buffer.len()
        };

        reader.consume(len);
    }

    reset_file_caches();
    Ok(newline_count)
}


pub fn count_newlines_direct_io(filename: &str) -> Result<usize, Error> {
    let mut open_options = File::options();
    open_options.read(true).custom_flags(libc::O_DIRECT);

    let mut file = open_options.open(filename)?;
    let mut buffer = vec![0; BUFFER_SIZE];
    let mut newline_count = 0;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let chunk_newline_count = buffer[..bytes_read].iter().filter(|&&b| b == b'\n').count();
        newline_count += chunk_newline_count;
    }
    reset_file_caches();
    Ok(newline_count)
}

pub fn count_newlines_memmap(filename: &str) -> Result<usize, Error> {
    let file = File::open(filename)?;
    let mmap = unsafe { Mmap::map(&file)? };
    mmap.advise(Advice::Sequential)?;

    let newline_count = mmap.iter().filter(|&&b| b == b'\n').count();
    reset_file_caches();
    Ok(newline_count)
}

pub unsafe fn count_newlines_memmap_avx2(filename: &str) -> Result<usize, Error> {
    let file = File::open(filename)?;
    let mmap = unsafe { Mmap::map(&file)? };
    mmap.advise(Advice::Sequential)?;

    let newline_byte = b'\n';
    let newline_vector = _mm256_set1_epi8(newline_byte as i8);
    let mut newline_count = 0;

    let mut ptr = mmap.as_ptr();
    let end_ptr = unsafe { ptr.add(mmap.len()) };

    while ptr <= end_ptr.sub(32) {
        let data = unsafe { _mm256_loadu_si256(ptr as *const __m256i) };
        let cmp_result = _mm256_cmpeq_epi8(data, newline_vector);
        let mask = _mm256_movemask_epi8(cmp_result);
        newline_count += mask.count_ones() as usize;
        ptr = unsafe { ptr.add(32) };
    }

    // Count remaining bytes
    let remaining_bytes = end_ptr as usize - ptr as usize;
    newline_count += mmap[mmap.len() - remaining_bytes..].iter().filter(|&&b| b == newline_byte).count();

    reset_file_caches();
    Ok(newline_count)
}

pub unsafe fn avx_hsum(a: __m256i) -> i32 {
    let zero = _mm256_setzero_si256();
    let unpacked_lo = _mm256_unpacklo_epi8(a, zero);
    let unpacked_hi = _mm256_unpackhi_epi8(a, zero);

    let sum16_lo = _mm256_hadd_epi16(unpacked_lo, unpacked_hi);
    let sum16_lo1 = _mm256_hadd_epi16(sum16_lo, zero);
    let sum16_lo2 = _mm256_hadd_epi16(sum16_lo1, zero);
    let sum16_lo3 = _mm256_hadd_epi16(sum16_lo2, zero);

    let result = _mm256_extract_epi16::<0>(sum16_lo3) + _mm256_extract_epi16::<8>(sum16_lo3);
    result as i32
}

pub unsafe fn count_newlines_memmap_avx2_running_sum(filename: &str) -> Result<usize, Error> {
    let file = File::open(filename)?;
    let mmap = unsafe { Mmap::map(&file)? };
    mmap.advise(Advice::Sequential)?;

    let newline_byte = b'\n';
    let newline_vector = _mm256_set1_epi8(newline_byte as i8);

    let mut newline_count = 0;
    let mut running_sum = _mm256_setzero_si256();

    let mut ptr = mmap.as_ptr();
    let end_ptr = unsafe { ptr.add(mmap.len()) };

    let mut iteration_count = 0;
    let ones_mask = _mm256_set1_epi8(1);

    while ptr <= end_ptr.sub(32) {

        let data = unsafe { _mm256_loadu_si256(ptr as *const __m256i) };
        let cmp_result = _mm256_cmpeq_epi8(data, newline_vector);
        let masked_ones = _mm256_and_si256(cmp_result, ones_mask);

        running_sum = _mm256_add_epi8(running_sum, masked_ones);

        ptr = unsafe { ptr.add(32) };
        iteration_count += 1;

        if iteration_count % 128 == 0 {
            newline_count += avx_hsum(running_sum) as usize;
            running_sum = _mm256_setzero_si256();
        }
    }

    // Process remaining iterations
    if iteration_count % 128 != 0 {
        newline_count += avx_hsum(running_sum) as usize;
    }

    // Count remaining bytes
    let remaining_bytes = end_ptr as usize - ptr as usize;
    newline_count += mmap[mmap.len() - remaining_bytes..].iter().filter(|&&b| b == newline_byte).count();

    reset_file_caches();

    Ok(newline_count)
}


pub unsafe fn count_newlines_memmap_avx512(filename: &str) -> Result<usize, Error> {
    let file = File::open(filename)?;
    let mmap = unsafe { Mmap::map(&file)? };
    mmap.advise(Advice::Sequential)?;

    let newline_byte = b'\n';
    let newline_vector = _mm512_set1_epi8(newline_byte as i8);
    let mut newline_count = 0;

    let mut ptr = mmap.as_ptr();
    let end_ptr = unsafe { ptr.add(mmap.len()) };

    while ptr <= end_ptr.sub(64) {
        let data = unsafe { _mm512_loadu_si512(ptr as *const i32) };
        let cmp_result = _mm512_cmpeq_epi8_mask(data, newline_vector);
        newline_count += cmp_result.count_ones() as usize;
        ptr = unsafe { ptr.add(64) };
    }

    // Count remaining bytes
    let remaining_bytes = end_ptr as usize - ptr as usize;
    newline_count += mmap[mmap.len() - remaining_bytes..].iter().filter(|&&b| b == newline_byte).count();

    reset_file_caches();
    Ok(newline_count)
}


pub fn count_newlines_vectored_io(path: &str) -> Result<usize, Error>  {
    let mut file = File::open(path)?;

    let mut buffers_: Vec<_> = (0..NUM_BUFFERS).map(|_| vec![0; BUFFER_SIZE]).collect();
    let mut buffers: Vec<_> = buffers_.iter_mut().map(|buf| io::IoSliceMut::new(buf)).collect();

    let mut newline_count = 0;

    loop {
        let bytes_read = file.read_vectored(&mut buffers)?;
        if bytes_read == 0 {
            break;
        }

        // Calculate how many buffers were filled
        let filled_buffers = bytes_read / BUFFER_SIZE;

        // Process the fully filled buffers
        for buf in &buffers[..filled_buffers] {
            newline_count += buf.iter().filter(|&&b| b == b'\n').count();
        }

        // Handle the potentially partially filled last buffer
        if filled_buffers < buffers.len() {
            let last_buffer = &buffers[filled_buffers];
            let end = bytes_read % BUFFER_SIZE;
            newline_count += last_buffer[..end].iter().filter(|&&b| b == b'\n').count();
        }
    }
    Ok(newline_count)
}

pub fn count_lines_io_uring(path: &str) -> io::Result<usize> {
    let file = File::open(path)?;
    let fd = file.as_raw_fd();

    let mut ring = IoUring::new(8)?;
    let mut line_count = 0;
    let mut offset = 0;

    let mut buf = vec![0; 4096];
    let mut read_size = buf.len();

    loop {
        let mut sqe = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), read_size as _)
            .offset(offset as _)
            .build()
            .user_data(line_count as _);

        unsafe {
            ring.submission()
                .push(&mut sqe)
                .expect("submission queue is full");
        }

        ring.submit_and_wait(1)?;

        let cqe = ring.completion().next().expect("completion queue is empty");

        let bytes_read = cqe.result() as usize;
        line_count = cqe.user_data() as usize;

        if bytes_read == 0 {
            break;
        }

        let data = &buf[..bytes_read];
        line_count += data.iter().filter(|&&b| b == b'\n').count();

        offset += bytes_read as u64;
        read_size = (buf.len() - (offset as usize % buf.len())) as usize;
    }
    Ok(line_count)
}

pub fn count_lines_io_uring_vectored(path: &str) -> io::Result<usize> {
    let file = File::open(path)?;
    let fd = file.as_raw_fd();

    let mut ring = IoUring::new(NUM_BUFFERS as u32)?;
    let mut line_count = 0;
    let mut offset = 0;

    let mut buffers = vec![vec![0; 8192]; NUM_BUFFERS];
    let mut iovecs: Vec<iovec> = buffers
        .iter_mut()
        .map(|buf| iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        })
        .collect();

    loop {
        let mut sqe = opcode::Readv::new(types::Fd(fd), iovecs.as_mut_ptr(), iovecs.len() as _)
            .offset(offset as _)
            .build()
            .user_data(0);

        unsafe {
            ring.submission()
                .push(&mut sqe)
                .expect("submission queue is full");
        }

        ring.submit_and_wait(1)?;

        let cqe = ring.completion().next().expect("completion queue is empty");
        let bytes_read = cqe.result() as usize;

        if bytes_read == 0 {
            break;
        }

        let mut buffer_line_count = 0;
        let mut remaining_bytes = bytes_read;
        for buf in &buffers[..iovecs.len()] {
            let buf_size = buf.len();
            let data_size = remaining_bytes.min(buf_size);
            let data = &buf[..data_size];
            buffer_line_count += data.iter().filter(|&&b| b == b'\n').count();
            remaining_bytes -= data_size;
            if remaining_bytes == 0 {
                break;
            }
        }
        line_count += buffer_line_count;

        offset += bytes_read as u64;
    }
    Ok(line_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::arch::x86_64::*;

    #[test]
    fn test_avx_hsum_all_ones() {
        unsafe {
            let a = _mm256_set1_epi8(1);
            let expected_sum = 32;
            let result = avx_hsum(a);
            assert_eq!(result, expected_sum);
        }
    }

    #[test]
    fn test_avx_hsum_all_zeros() {
        unsafe {
            let a = _mm256_setzero_si256();
            let expected_sum = 0;
            let result = avx_hsum(a);
            assert_eq!(result, expected_sum);
        }

    }

    #[test]
    fn test_avx_hsum_alternating_values() {
        unsafe {
            let a = _mm256_set_epi8(
                1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2,
                1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2,
            );
            let expected_sum = 48;
            let result = avx_hsum(a);
            assert_eq!(result, expected_sum);
        }
    }

}