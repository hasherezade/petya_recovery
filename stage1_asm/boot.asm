; mini bootloader for educational purposes
;
; CC-BY: hasherezade
;
; compile:
; nasm boot.asm -f bin -o boot.bin
; 
; Copy to flash disk (as root)
; example if the flash disk is /dev/sdb:
; dd if=boot.bin of=/dev/sdb bs=512 count=1
;

[bits 16]
[org 0x7C00]

;macros

%macro PRINT_STR 1 ;buffer
push si
mov si, %1
call puts
pop si
%endmacro

%macro GETC 0
 mov ah, 0
 int 0x16
%endmacro

%macro PUTC 0
  mov ah, 0x0E
  mov bx, 0x11
  int 0x10
%endmacro

%macro GET_STR 1 ;buffer
 mov di, %1
 call gets
%endmacro

%macro CHECK_DISK 1 ; drive
 mov dl, %1 ;drive
 call find_disk
%endmacro

%macro PRINT_BYTE 1 ; buffer
 mov si, %1
 mov al, BYTE[si]
 call print_byte
 PRINT_STR enter_key
%endmacro

%macro READ_SECTOR 2 ; buffer, sector_number
 mov di, %1
 mov cl, %2
 call read_sector
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;code
main:
 xor ax,ax
 mov ds,ax
 mov es,ax
 PRINT_STR banner

 CHECK_DISK 0
 CHECK_DISK 1
 CHECK_DISK 0x80
 CHECK_DISK 0x81
 PRINT_STR fin_banner
 GETC
 int 0x19

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; SI - string
puts:
  lodsb
  cmp BYTE al, 0
  je puts_end
    PUTC
    jmp puts
  puts_end:
    ret

; AL - byte to be printed
print_byte:
 push ax
 and al, 0xF0
 sar al, 0x4
 call to_hex_ascii
 PUTC
 pop ax ;recover original value
 call to_hex_ascii
 PUTC
 ret

to_hex_ascii:
 and al, 0x0F
 cmp al, 0xA
 jb num
  sub al, 0xA
  add al, 'A'
 jmp end_to_hex_ascii
 num:
  add al, '0'
 end_to_hex_ascii:
ret

;DI - output
;CL -sector number
read_sector:
  mov bx, di ; buffer
  mov ah, 0x02 ; read
  mov al, 0x01 ; sector count
  mov dh, 0x00 ; head
  mov ch, 0x00 ; track
  int 0x13
  xor ax,ax
  jnc read_success
  jmp read_end
  read_success:
  mov ax,1
  read_end:
  ret

;AL -disk id
print_disk_info:
 push ax
 cmp al, 0x80
 jnb _print_hd
 PRINT_STR floppy_label
 jmp label_printed
 _print_hd:
 PRINT_STR hd_label
 label_printed:
 pop ax
 and ax, 0x0F
 call print_byte
 PRINT_STR enter_key
 ret

read_key:
 ;READ_SECTOR 0x8000, 55
 PRINT_STR stage1_key
 mov si, 0x8001
 mov cx, 32
 key_next_char:
 test cx,cx
 jz key_end
  mov al, BYTE [si]
  sub al, 'z'
  dec cx
  inc si
  mov bl, BYTE[si]
  shr bl, 1
  dec cx
  inc si
  cmp al, bl
  jnz stage1_key_failed
  PUTC
  jmp key_next_char
 stage1_key_failed:
 PRINT_STR enter_key
 PRINT_STR stage1_failed
 key_end:
 PRINT_STR enter_key
 ret

; DL - drive
; buffer pointer: 0x8000
find_disk:
  mov BYTE [curr_disk], dl
  xor ah, ah ;reset
  int 0x13
  jc find_disk_end ;operation failed

  xor ax,ax
  mov dl, BYTE[curr_disk]
  READ_SECTOR 0x8000, 55
  test ax,ax
  jz find_disk_end ; carry bit is set on read error
   mov ax, WORD[0x8029]
   cmp ax, 0x7468 ;68 74 74 70
   jne find_disk_end
   mov ax, WORD[0x8029+2]
   cmp ax, 0x7074
   jne find_disk_end
   mov dl, BYTE[curr_disk]
   PRINT_STR infected_found
   mov al, dl
   call print_disk_info
   call read_key
  find_disk_end:
  ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;data
enter_key db 13, 10, 0
banner db 'Checking disks...', 13, 10, 0
fin_banner db 'Press any key to boot from the disk', 13, 10, 0

hd_label db '> Hard disk: ', 0
floppy_label db '> Floppy: ', 0
infected_found db 'PETYA detected in:', 13, 10, 0
stage1_key db 'Stage1 key: ', 0
stage1_failed db 'Could not recover stage 1 key.', 10,13,0
curr_disk db 0
times 510-($-$$) db 0	;padding
dw 0xAA55		;end signature
