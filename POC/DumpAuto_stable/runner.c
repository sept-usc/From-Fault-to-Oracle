#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fsync_file(FILE *fp) {
    if (!fp) return -1;
    if (fflush(fp) != 0) return -1;
    int fd = fileno(fp);
    if (fd < 0) return -1;
    if (fsync(fd) != 0) return -1;
    return 0;
}

/*
 * Read the key of the last valid record from dump.log, in the form 0xADDR:0xVALUE.
 * Success: return 0 and store the last address in *out_addr.
 * Failure: return -1 if the file is missing, empty, or has no valid lines.
 */
static int read_last_key_from_log(const char *log_path, uint32_t *out_addr) {
    FILE *fp = fopen(log_path, "r");
    if (!fp) return -1;

    char line[256];
    uint32_t last = 0;
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;

        *colon = '\0';

        char *endp = NULL;
        errno = 0;
        unsigned long a = strtoul(line, &endp, 0);
        if (errno != 0 || endp == line || a > 0xFFFFFFFFul) continue;

        last = (uint32_t)a;
        found = 1;
    }

    fclose(fp);
    if (!found) return -1;
    *out_addr = last;
    return 0;
}

/*
 * Extract the value from the last "content: 0x...." occurrence in child output.
 * Return 0 on success and write the value to *out_value.
 */
static int extract_content_value_from_stream(int read_fd, uint32_t *out_value) {
    char buf[4096];
    char line[8192];
    size_t linelen = 0;

    int found = 0;
    uint32_t last_value = 0;

    while (1) {
        ssize_t n = read(read_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read(pipe)");
            return -1;
        }
        if (n == 0) break;

        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (linelen + 1 < sizeof(line)) {
                line[linelen++] = c;
            }

            if (c == '\n') {
                line[linelen] = '\0';

                char *p = strstr(line, "content:");
                if (p) {
                    char *hx = strstr(p, "0x");
                    if (hx) {
                        errno = 0;
                        unsigned long v = strtoul(hx, NULL, 16);
                        if (errno == 0 && v <= 0xFFFFFFFFul) {
                            last_value = (uint32_t)v;
                            found = 1;
                        }
                    }
                }
                linelen = 0;
            }
        }
    }

    // last line w/o '\n'
    if (linelen > 0) {
        line[linelen] = '\0';
        char *p = strstr(line, "content:");
        if (p) {
            char *hx = strstr(p, "0x");
            if (hx) {
                errno = 0;
                unsigned long v = strtoul(hx, NULL, 16);
                if (errno == 0 && v <= 0xFFFFFFFFul) {
                    last_value = (uint32_t)v;
                    found = 1;
                }
            }
        }
    }

    if (!found) return -1;
    *out_value = last_value;
    return 0;
}

/*
 * Execute cracktpu once and write the result to *out_value.
 * Return 0 on success, or -1 on failure.
 * Use an output parameter instead of the return value so 0xFFFFFFFF is not mistaken for -1.
 */
static int run_once_simple(const char *bin, uint32_t addr, uint32_t *out_value) {
    char addr_hex[16];
    snprintf(addr_hex, sizeof(addr_hex), "0x%08" PRIx32, addr);

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(pipefd[1], STDERR_FILENO) < 0) _exit(127);
        close(pipefd[1]);
        execl(bin, bin, addr_hex, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);

    uint32_t value = 0;
    int parse_ok = extract_content_value_from_stream(pipefd[0], &value);
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    int rc = -1;
    if (WIFEXITED(status))   rc = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) rc = 128 + WTERMSIG(status);

    if (rc != 0 || parse_ok != 0) return -1;

    *out_value = value;
    return 0;
}

/*
 * Repeatedly read addr until the same value appears stable_required times in a row,
 * then write it to the log.
 * interval_s: seconds to wait between reads, allowing the cache to settle.
 * max_tries: maximum number of attempts.
 * Return 0 on success, or -1 if the value is still unstable after max_tries.
 */
static int run_until_stable(const char *bin, uint32_t addr, FILE *log_fp,
                             int stable_required, int interval_s, int max_tries) {
    int consecutive = 0;
    int unstable = 0;   // The value changed during the read attempts.
    uint32_t prev = 0;

    for (int t = 0; t < max_tries; t++) {
        uint32_t v = 0;
        if (run_once_simple(bin, addr, &v) != 0) {
            consecutive = 0;
            fprintf(stderr, "[!] addr=0x%08" PRIx32 " read failed (try %d/%d)\n",
                    addr, t + 1, max_tries);
            sleep(2);
            continue;
        }

        if (consecutive > 0 && v == prev) {
            consecutive++;
        } else {
            if (consecutive > 0) {
                fprintf(stderr, "[~] addr=0x%08" PRIx32
                        " value changed: 0x%08" PRIx32 " -> 0x%08" PRIx32
                        " (try %d/%d), reset\n",
                        addr, prev, v, t + 1, max_tries);
                unstable = 1;
            }
            consecutive = 1;
            prev = v;
        }

        fprintf(stderr, "[.] addr=0x%08" PRIx32 " value=0x%08" PRIx32
                " consecutive=%d/%d\n", addr, v, consecutive, stable_required);

        if (consecutive >= stable_required) {
            if (unstable) {
                fprintf(log_fp, "0x%08" PRIx32 ":0x%08" PRIx32 ":cache_unstable\n", addr, v);
            } else {
                fprintf(log_fp, "0x%08" PRIx32 ":0x%08" PRIx32 "\n", addr, v);
            }
            fsync_file(log_fp);
            return 0;
        }

        if (t + 1 < max_tries) sleep(interval_s);
    }

    return -1;
}

/*
 * Fallback reconstruction: if directly reading addr fails, reconstruct the target
 * 4 bytes from neighboring addresses in little-endian order.
 */
static int triple_insurance_operation(const char *bin, uint32_t addr, FILE *log_fp) {
    // Strategy 2_2: read addr-2 and addr+2.
    uint32_t r1 = 0, r2 = 0;
    if (run_once_simple(bin, addr - 2, &r1) == 0 &&
        run_once_simple(bin, addr + 2, &r2) == 0) {
        uint16_t lo = (uint16_t)(r1 >> 16);      // High 2 bytes at addr-2 = low 2 target bytes.
        uint16_t hi = (uint16_t)(r2 & 0xFFFFu);  // Low 2 bytes at addr+2 = high 2 target bytes.
        fprintf(stderr, "insurance_2_2: read(0x%08" PRIx32 ")=0x%08" PRIx32
                " read(0x%08" PRIx32 ")=0x%08" PRIx32
                " lo=0x%04" PRIx16 " hi=0x%04" PRIx16 "\n",
                addr - 2, r1, addr + 2, r2, lo, hi);
        uint32_t merged = ((uint32_t)hi << 16) | (uint32_t)lo;
        fprintf(log_fp, "0x%08" PRIx32 ":0x%08" PRIx32 ":flag_insurance_operation_2_2\n",
                addr, merged);
        fsync_file(log_fp);
        return 0;
    }

    // Strategy 1_3: read addr-3 and addr+1.
    uint32_t r3 = 0, r4 = 0;
    if (run_once_simple(bin, addr - 3, &r3) == 0 &&
        run_once_simple(bin, addr + 1, &r4) == 0) {
        uint8_t  low1  = (uint8_t)(r3 >> 24);        // Highest byte at addr-3 = target byte0.
        uint32_t high3 = r4 & 0x00FFFFFFu;           // Low 3 bytes at addr+1 = target bytes 1..3.
        uint32_t merged2 = (high3 << 8) | (uint32_t)low1;
        fprintf(log_fp, "0x%08" PRIx32 ":0x%08" PRIx32 ":flag_insurance_operation_1_3\n",
                addr, merged2);
        fsync_file(log_fp);
        return 0;
    }

    // Strategy 3_1: read addr-1 and addr+3.
    uint32_t r5 = 0, r6 = 0;
    if (run_once_simple(bin, addr - 1, &r5) == 0 &&
        run_once_simple(bin, addr + 3, &r6) == 0) {
        uint32_t low3  = (r5 & 0xFFFFFF00u) >> 8;   // High 3 bytes at addr-1 = target bytes 0..2.
        uint8_t  high1 = (uint8_t)(r6 & 0xFFu);     // Lowest byte at addr+3 = target byte3.
        uint32_t merged3 = ((uint32_t)high1 << 24) | (low3 & 0x00FFFFFFu);
        fprintf(log_fp, "0x%08" PRIx32 ":0x%08" PRIx32 ":flag_insurance_operation_3_1\n",
                addr, merged3);
        fsync_file(log_fp);
        return 0;
    }

    return -1;
}

int main(int argc, char **argv) {
    const char *bin      = "./cracktpu";
    const char *log_path = "0x10000000_0x100E8BBF_dump.log";

    uint32_t start = 0x10000000;
    uint32_t end   = 0x100E8BBF;
    uint32_t step  = 4;

    if (argc >= 2) {
        char *endptr = NULL;
        start = (uint32_t)strtoul(argv[1], &endptr, 0);
        if (endptr == argv[1] || *endptr != '\0') {
            fprintf(stderr, "invalid start address: %s\n", argv[1]);
            return 1;
        }
    }

    if (argc >= 3) {
        char *endptr = NULL;
        end = (uint32_t)strtoul(argv[2], &endptr, 0);
        if (endptr == argv[2] || *endptr != '\0') {
            fprintf(stderr, "invalid end address: %s\n", argv[2]);
            return 1;
        }
    }

    if (argc >= 4) bin = argv[3];
    if (argc >= 5) log_path = argv[4];

    char log_name_default[256];
    snprintf(log_name_default, sizeof(log_name_default), "0x%08x_0x%08x_dump.log", start, end);
    if (argc < 5) {
        log_path = log_name_default;
    }

    // Stability parameters.
    const int STABLE_REQUIRED   = 3;   // Number of consecutive identical reads required before logging.
    const int STABLE_INTERVAL_S = 2;   // Seconds to wait between reads, allowing the cache to settle.
    const int MAX_STABLE_TRIES  = 15;  // Use fallback reconstruction if still unstable after this many tries.

    // Resume from dump.log: start at the address immediately after the last key.
    uint32_t last = 0;
    if (read_last_key_from_log(log_path, &last) == 0) {
        uint32_t resume = last + step;
        if (resume >= end) {
            fprintf(stderr, "[*] dump already complete (last=0x%08" PRIx32
                    "), nothing to do\n", last);
            return 0;
        } else if (resume >= start && resume < end && ((resume - start) % step == 0)) {
            start = resume;
            fprintf(stderr, "[*] resume from dump.log last key: 0x%08" PRIx32
                    " -> next 0x%08" PRIx32 "\n", last, start);
        } else {
            fprintf(stderr, "[!] last key in log out of range or misaligned: "
                    "0x%08" PRIx32 ", ignore\n", last);
        }
    }

    FILE *log_fp = fopen(log_path, "a");
    if (!log_fp) {
        perror("fopen(dump.log)");
        return 1;
    }

    for (uint32_t addr = start; addr < end; addr += step) {
        printf("[*] addr=0x%08" PRIx32 "\n", addr);

        int ok = 0;

        if (run_until_stable(bin, addr, log_fp,
                             STABLE_REQUIRED, STABLE_INTERVAL_S,
                             MAX_STABLE_TRIES) == 0) {
            ok = 1;
        }

        if (!ok) {
            fprintf(stderr, "[!] addr=0x%08" PRIx32
                    " unstable after %d tries, trying triple_insurance\n",
                    addr, MAX_STABLE_TRIES);
            if (triple_insurance_operation(bin, addr, log_fp) == 0) {
                ok = 1;
            } else {
                fprintf(stderr, "[!] triple_insurance_operation failed at "
                        "0x%08" PRIx32 "\n", addr);
            }
        }

        if (!ok) {
            fprintf(stderr, "[!] giving up at addr=0x%08" PRIx32 "\n", addr);
            fclose(log_fp);
            return 1;
        }
    }

    fclose(log_fp);
    return 0;
}
