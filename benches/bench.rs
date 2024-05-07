use criterion::{criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::io::{Error, Read, self, IoSliceMut, BufRead, BufReader};
use std::os::unix::fs::OpenOptionsExt;
use memmap2::Mmap;
use std::process::Command;
use std::os::unix::io::AsRawFd;
use io_uring::{opcode, types, IoUring};
use libc::iovec;

const BUFFER_SIZE: usize = 8192;
const NUM_BUFFERS: usize = 32;
fn get_filename() -> String {
    std::env::var("IO_BENCH_DATA_FILE").unwrap()
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

fn count_newlines_standard(filename: &str) -> Result<usize, std::io::Error> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    let newline_count = reader.lines().count();

    reset_file_caches();
    Ok(newline_count)
}


fn count_newlines_direct_io(filename: &str) -> Result<usize, Error> {
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

fn count_newlines_memmap(filename: &str) -> Result<usize, Error> {
    let file = File::open(filename)?;
    let mmap = unsafe { Mmap::map(&file)? };

    let newline_count = mmap.iter().filter(|&&b| b == b'\n').count();
    reset_file_caches();
    Ok(newline_count)
}



fn count_newlines_vectored_io(path: &str) -> Result<usize, Error>  {
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

fn count_lines_io_uring(path: &str) -> io::Result<usize> {
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

fn count_lines_io_uring_vectored(path: &str) -> io::Result<usize> {
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

pub fn criterion_benchmark(c: &mut Criterion) {
    let path = get_filename();
    c.bench_function("count_newlines_direct_io", |b| b.iter(|| count_newlines_direct_io(path.as_str())));
    c.bench_function("count_newlines_standard", |b| b.iter(|| count_newlines_standard(path.as_str())));
    c.bench_function("count_newlines_memmap", |b| b.iter(|| count_newlines_memmap(path.as_str())));
    c.bench_function("count_newlines_vectored_io", |b| b.iter(|| count_newlines_vectored_io(path.as_str())));
    c.bench_function("count_lines_io_uring", |b| b.iter(|| count_lines_io_uring(path.as_str())));
    c.bench_function("count_lines_io_uring_vectored", |b| b.iter(|| count_lines_io_uring_vectored(path.as_str())));
}

criterion_group!(name=benches; config=Criterion::default().sample_size(10); targets=criterion_benchmark);
criterion_main!(benches);