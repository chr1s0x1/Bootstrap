//
//  krw.h
//  Bootstrap
//
//  Created by Chris Coding on 1/12/24.
//

#ifndef krw_h
#define krw_h

uint64_t exploit_runner(const char *exploit_string, uint64_t pages);

void early_kread(uint64_t kfd, uint64_t kaddr, void* uaddr, uint64_t size);

uint64_t early_kread64(uint64_t kfd, uint64_t where);

uint32_t early_kread32(uint64_t kfd, uint64_t where);

void early_kreadbuf(uint64_t kfd, uint64_t kaddr, void* output, size_t size);

uint64_t get_kslide(void) ;

uint64_t get_kernproc(void);

uint64_t get_selftask(void);

uint64_t get_selfproc(void);

uint64_t get_selfpmap(void);

uint64_t get_kerntask(void);

extern uint64_t return_kfd(void);

void init_krw(uint64_t kfd_addr);

uint8_t kread8(uint64_t where);

uint32_t kread16(uint64_t where);

uint32_t kread32(uint64_t where);

uint64_t kread64(uint64_t where);

//Thanks @jmpews
uint64_t kread64_smr(uint64_t where);

void kwrite8(uint64_t where, uint8_t what);

void kwrite16(uint64_t where, uint16_t what);

void kwrite32(uint64_t where, uint32_t what);

void kwrite64(uint64_t where, uint64_t what);

uint64_t do_vtophys(uint64_t what);

uint64_t do_phystokv(uint64_t what);

uint64_t kread64_ptr(uint64_t kaddr);

void kreadbuf(uint64_t kaddr, void* output, size_t size);


#endif /* krw_h */
