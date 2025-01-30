/*
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 100
#define DATA "Benchmark Write Test"

// Define the memory size as 256MB
#define MEMORY_SIZE (256 * 1024 * 1024)      // 256MB
#define WRITE_OFFSET (1 * 1024 * 1024)       // 1MB offset

// Function to calculate time difference in microseconds
long long time_diff_us(struct timespec start, struct timespec end) {
    long long start_us = start.tv_sec * 1000000LL + start.tv_nsec / 1000;
    long long end_us = end.tv_sec * 1000000LL + end.tv_nsec / 1000;
    return end_us - start_us;
}

int main() {
    // -------------------------------
    // Benchmarking Standard DRAM
    // -------------------------------
    printf("Starting DRAM Write Benchmark (256MB)...\n");
    // Allocate memory using malloc
    size_t ram_size = MEMORY_SIZE; // 256MB
    char *ram_buffer = malloc(ram_size);
    if (!ram_buffer) {
        perror("Failed to allocate DRAM");
        exit(EXIT_FAILURE);
    }

    // Initialize buffer
    memset(ram_buffer, 'A', ram_size);

    long long total_ram_write_time = 0;

    for(int i = 0; i < ITERATIONS; i++) {
        struct timespec start, end;
        // Start timer
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
            perror("clock_gettime");
            free(ram_buffer);
            exit(EXIT_FAILURE);
        }

        // Write operation
        memcpy(ram_buffer + WRITE_OFFSET, DATA, strlen(DATA) + 1); // 1MB offset

        // End timer
        if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
            perror("clock_gettime");
            free(ram_buffer);
            exit(EXIT_FAILURE);
        }

        long long write_time = time_diff_us(start, end);
        total_ram_write_time += write_time;

        printf("DRAM Iteration %d: Write Time = %lld us\n", i+1, write_time);
    }

    double average_ram_write_time = (double)total_ram_write_time / ITERATIONS;
    printf("Average DRAM Write Latency over %d iterations: %.2f us\n\n", ITERATIONS, average_ram_write_time);

    // Free DRAM buffer
    free(ram_buffer);

    // -------------------------------
    // Benchmarking DAX Node (PMEM)
    // -------------------------------
    printf("Starting DAX Node (PMEM) Write Benchmark (256MB)...\n");
    // Open /dev/dax0.0
    int fd = open("/dev/dax0.0", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/dax0.0");
        exit(EXIT_FAILURE);
    }

    // Define PMEM size as 256MB
    size_t pmem_size = MEMORY_SIZE; // 256MB
    char *pmem_addr = mmap(NULL, pmem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pmem_addr == MAP_FAILED) {
        perror("Failed to mmap /dev/dax0.0");
        close(fd);
        exit(EXIT_FAILURE);
    }

    long long total_pmem_write_time = 0;

    for(int i = 0; i < ITERATIONS; i++) {
        struct timespec start, end;
        // Start timer
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
            perror("clock_gettime");
            munmap(pmem_addr, pmem_size);
            close(fd);
            exit(EXIT_FAILURE);
        }

        // Write operation
        memcpy(pmem_addr + WRITE_OFFSET, DATA, strlen(DATA) + 1); // 1MB offset


        // End timer
        if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
            perror("clock_gettime");
            munmap(pmem_addr, pmem_size);
            close(fd);
            exit(EXIT_FAILURE);
        }

        long long write_time = time_diff_us(start, end);
        total_pmem_write_time += write_time;

        printf("PMEM Iteration %d: Write Time = %lld us\n", i+1, write_time);
    }

    double average_pmem_write_time = (double)total_pmem_write_time / ITERATIONS;
    printf("Average PMEM Write Latency over %d iterations: %.2f us\n", ITERATIONS, average_pmem_write_time);

    // Clean up PMEM resources
    munmap(pmem_addr, pmem_size);
    close(fd);

    return 0;
}
*/


// compare_latency_improved.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define ITERATIONS 100
#define DATA_SIZE 1024 // 1KB
#define DATA_PATTERN 'B'

// Function to calculate time difference in nanoseconds
long long time_diff_ns(struct timespec start, struct timespec end) {
    long long start_ns = start.tv_sec * 1000000000LL + start.tv_nsec;
    long long end_ns = end.tv_sec * 1000000000LL + end.tv_nsec;
    return end_ns - start_ns;
}

int main() {
    // -------------------------------
    // Benchmarking Standard DRAM
    // -------------------------------
    printf("Starting DRAM Write Benchmark (256MB)...\n");
    
    // Allocate memory using malloc
    size_t ram_size = 256 * 1024 * 1024; // 256MB
    volatile char *ram_buffer = malloc(ram_size);
    if (!ram_buffer) {
        perror("Failed to allocate DRAM");
        exit(EXIT_FAILURE);
    }

    // Initialize buffer
    memset((void*)ram_buffer, 'A', ram_size);

    long long total_ram_write_time = 0;

    for(int i = 0; i < ITERATIONS; i++) {
        struct timespec start, end;
        
        // Start timer
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) == -1) {
            perror("clock_gettime");
            free((void*)ram_buffer);
            exit(EXIT_FAILURE);
        }

        // Write operation: 1KB
        memset((void*)(ram_buffer + (1 * 1024 * 1024)), DATA_PATTERN, DATA_SIZE);

        // End timer
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) == -1) {
            perror("clock_gettime");
            free((void*)ram_buffer);
            exit(EXIT_FAILURE);
        }

        long long write_time = time_diff_ns(start, end);
        total_ram_write_time += write_time;

        printf("DRAM Iteration %d: Write Time = %lld ns\n", i+1, write_time);
    }

    double average_ram_write_time = (double)total_ram_write_time / ITERATIONS;
    printf("Average DRAM Write Latency over %d iterations: %.2f ns\n\n", ITERATIONS, average_ram_write_time);

    // Free DRAM buffer
    free((void*)ram_buffer);

    // -------------------------------
    // Benchmarking DAX Node (PMEM)
    // -------------------------------
    printf("Starting DAX Node (PMEM) Write Benchmark (256MB)...\n");
    
    // Open /dev/dax0.0
    int fd = open("/dev/dax0.0", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/dax0.0");
        exit(EXIT_FAILURE);
    }

    // Define PMEM size as 256MB
    size_t pmem_size = 256 * 1024 * 1024; // 256MB
    volatile char *pmem_addr = mmap(NULL, pmem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pmem_addr == MAP_FAILED) {
        perror("Failed to mmap /dev/dax0.0");
        close(fd);
        exit(EXIT_FAILURE);
    }

    long long total_pmem_write_time = 0;

    for(int i = 0; i < ITERATIONS; i++) {
        struct timespec start, end;
        
        // Start timer
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) == -1) {
            perror("clock_gettime");
            munmap((void*)pmem_addr, pmem_size);
            close(fd);
            exit(EXIT_FAILURE);
        }

        // Write operation: 1KB
        memset((void*)(pmem_addr + (1 * 1024 * 1024)), DATA_PATTERN, DATA_SIZE);


        // End timer
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) == -1) {
            perror("clock_gettime");
            munmap((void*)pmem_addr, pmem_size);
            close(fd);
            exit(EXIT_FAILURE);
        }

        long long write_time = time_diff_ns(start, end);
        total_pmem_write_time += write_time;

        printf("PMEM Iteration %d: Write Time = %lld ns\n", i+1, write_time);
    }

    double average_pmem_write_time = (double)total_pmem_write_time / ITERATIONS;
    printf("Average PMEM Write Latency over %d iterations: %.2f ns\n", ITERATIONS, average_pmem_write_time);

    // Clean up PMEM resources
    munmap((void*)pmem_addr, pmem_size);
    close(fd);

    return 0;
}
