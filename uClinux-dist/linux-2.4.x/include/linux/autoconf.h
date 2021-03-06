/*
 * Automatically generated C config: don't edit
 */
#define AUTOCONF_INCLUDED
#define CONFIG_ARM 1
#undef  CONFIG_SBUS
#define CONFIG_UID16 1
#define CONFIG_RWSEM_GENERIC_SPINLOCK 1
#define CONFIG_UCLINUX 1
#define MAGIC_ROM_PTR 1

/*
 * Code maturity level options
 */
#define CONFIG_EXPERIMENTAL 1
#undef  CONFIG_OBSOLETE

/*
 * Loadable module support
 */
#undef  CONFIG_MODULES

/*
 * System Type
 */
#define CONFIG_ARCH_DSC21 1
#undef  CONFIG_ARCH_CNXT
#undef  CONFIG_ARCH_SWARM
#undef  CONFIG_ARCH_ATMEL
#define CONFIG_CPU_ARM710 1
#define CONFIG_CPU_32 1
#undef  CONFIG_CPU_26
#define CONFIG_NO_PGT_CACHE 1
#define CONFIG_CPU_WITH_CACHE 1
#define CONFIG_CPU_WITH_MCR_INSTRUCTION 1
#define DRAM_BASE 0x08000000
#define DRAM_SIZE 0x00200000
#define FLASH_MEM_BASE 0x08400000
#define FLASH_SIZE 0x00200000
#define CONFIG_DUMMY_CONSOLE 1

/*
 * General setup
 */
#undef  CONFIG_HOTPLUG
#undef  CONFIG_PCMCIA
#define CONFIG_NET 1
#undef  CONFIG_SYSVIPC
#undef  CONFIG_REDUCED_MEMORY
#undef  CONFIG_BSD_PROCESS_ACCT
#undef  CONFIG_SYSCTL
#undef  CONFIG_NWFPE
#undef  CONFIG_KCORE_ELF
#define CONFIG_KCORE_AOUT 1
#define CONFIG_BINFMT_FLAT 1
#define CONFIG_KERNEL_ELF 1
#undef  CONFIG_PM
#undef  CONFIG_ARTHUR
#undef  CONFIG_ALIGNMENT_TRAP

/*
 * Networking options
 */
#define CONFIG_PACKET 1
#undef  CONFIG_PACKET_MMAP
#undef  CONFIG_NETLINK_DEV
#undef  CONFIG_NETFILTER
#undef  CONFIG_FILTER
#define CONFIG_UNIX 1
#define CONFIG_INET 1
#undef  CONFIG_IP_MULTICAST
#undef  CONFIG_IP_ADVANCED_ROUTER
#undef  CONFIG_IP_PNP
#undef  CONFIG_NET_IPIP
#undef  CONFIG_NET_IPGRE
#undef  CONFIG_ARPD
#undef  CONFIG_INET_ECN
#undef  CONFIG_SYN_COOKIES
#undef  CONFIG_IPV6
#undef  CONFIG_KHTTPD
#undef  CONFIG_ATM
#undef  CONFIG_VLAN_8021Q

/*
 *  
 */
#undef  CONFIG_IPX
#undef  CONFIG_ATALK
#undef  CONFIG_DECNET
#undef  CONFIG_BRIDGE
#undef  CONFIG_X25
#undef  CONFIG_LAPB
#undef  CONFIG_LLC
#undef  CONFIG_NET_DIVERT
#undef  CONFIG_ECONET
#undef  CONFIG_WAN_ROUTER
#undef  CONFIG_NET_FASTROUTE
#undef  CONFIG_NET_HW_FLOWCONTROL

/*
 * QoS and/or fair queueing
 */
#undef  CONFIG_NET_SCHED
#undef  CONFIG_IPSEC

/*
 * Network device support
 */
#define CONFIG_NETDEVICES 1

/*
 * ARCnet devices
 */
#undef  CONFIG_ARCNET
#undef  CONFIG_DUMMY
#undef  CONFIG_BONDING
#undef  CONFIG_EQUALIZER
#undef  CONFIG_TUN
#undef  CONFIG_ETHERTAP

/*
 * Ethernet (10 or 100Mbit)
 */
#define CONFIG_NET_ETHERNET 1
#undef  CONFIG_ARM_AM79C961A
#undef  CONFIG_SUNLANCE
#undef  CONFIG_SUNBMAC
#undef  CONFIG_SUNQE
#undef  CONFIG_SUNLANCE
#undef  CONFIG_SUNGEM
#undef  CONFIG_NET_VENDOR_3COM
#undef  CONFIG_LANCE
#undef  CONFIG_NET_VENDOR_SMC
#undef  CONFIG_NET_VENDOR_RACAL
#undef  CONFIG_NET_ISA
#undef  CONFIG_NET_PCI
#undef  CONFIG_NET_POCKET
#undef  CONFIG_FEC
#define CONFIG_CS89x0 1
#undef  CONFIG_UCCS89x0_HW_SWAP

/*
 * Ethernet (1000 Mbit)
 */
#undef  CONFIG_ACENIC
#undef  CONFIG_DL2K
#undef  CONFIG_MYRI_SBUS
#undef  CONFIG_NS83820
#undef  CONFIG_HAMACHI
#undef  CONFIG_YELLOWFIN
#undef  CONFIG_SK98LIN
#undef  CONFIG_FDDI
#undef  CONFIG_HIPPI
#undef  CONFIG_PLIP
#undef  CONFIG_PPP
#undef  CONFIG_SLIP

/*
 * Wireless LAN (non-hamradio)
 */
#undef  CONFIG_NET_RADIO

/*
 * Token Ring devices
 */
#undef  CONFIG_TR
#undef  CONFIG_NET_FC
#undef  CONFIG_RCPCI
#undef  CONFIG_SHAPER

/*
 * Wan interfaces
 */
#undef  CONFIG_WAN

/*
 * Amateur Radio support
 */
#undef  CONFIG_HAMRADIO

/*
 * IrDA (infrared) support
 */
#undef  CONFIG_IRDA

/*
 * ATA/IDE/MFM/RLL support
 */
#undef  CONFIG_IDE
#undef  CONFIG_BLK_DEV_IDE_MODES
#undef  CONFIG_BLK_DEV_HD

/*
 * SCSI support
 */
#undef  CONFIG_SCSI

/*
 * ISDN subsystem
 */
#undef  CONFIG_ISDN

/*
 * Parallel port support
 */
#undef  CONFIG_PARPORT

/*
 * Memory Technology Devices (MTD)
 */
#undef  CONFIG_MTD

/*
 * Plug and Play configuration
 */
#undef  CONFIG_PNP
#undef  CONFIG_ISAPNP

/*
 * Block devices
 */
#undef  CONFIG_BLK_DEV_FD
#undef  CONFIG_BLK_DEV_XD
#undef  CONFIG_PARIDE
#undef  CONFIG_BLK_CPQ_DA
#undef  CONFIG_BLK_CPQ_CISS_DA
#undef  CONFIG_BLK_DEV_DAC960
#undef  CONFIG_BLK_DEV_LOOP
#undef  CONFIG_BLK_DEV_NBD
#define CONFIG_BLK_DEV_RAM 1
#define CONFIG_BLK_DEV_RAM_SIZE (4096)
#undef  CONFIG_BLK_DEV_INITRD
#define CONFIG_BLK_DEV_BLKMEM 1

/*
 * File systems
 */
#undef  CONFIG_QUOTA
#undef  CONFIG_AUTOFS_FS
#undef  CONFIG_AUTOFS4_FS
#undef  CONFIG_REISERFS_FS
#undef  CONFIG_REISERFS_CHECK
#undef  CONFIG_REISERFS_PROC_INFO
#undef  CONFIG_ADFS_FS
#undef  CONFIG_ADFS_FS_RW
#undef  CONFIG_AFFS_FS
#undef  CONFIG_HFS_FS
#undef  CONFIG_BFS_FS
#undef  CONFIG_EXT3_FS
#undef  CONFIG_JBD
#undef  CONFIG_JBD_DEBUG
#undef  CONFIG_FAT_FS
#undef  CONFIG_MSDOS_FS
#undef  CONFIG_UMSDOS_FS
#undef  CONFIG_VFAT_FS
#undef  CONFIG_EFS_FS
#undef  CONFIG_JFFS_FS
#undef  CONFIG_JFFS2_FS
#undef  CONFIG_CRAMFS
#undef  CONFIG_TMPFS
#undef  CONFIG_RAMFS
#undef  CONFIG_ISO9660_FS
#undef  CONFIG_JOLIET
#undef  CONFIG_ZISOFS
#undef  CONFIG_MINIX_FS
#undef  CONFIG_VXFS_FS
#undef  CONFIG_NTFS_FS
#undef  CONFIG_NTFS_RW
#undef  CONFIG_HPFS_FS
#define CONFIG_PROC_FS 1
#undef  CONFIG_DEVFS_FS
#undef  CONFIG_DEVFS_MOUNT
#undef  CONFIG_DEVFS_DEBUG
#undef  CONFIG_DEVPTS_FS
#undef  CONFIG_QNX4FS_FS
#undef  CONFIG_QNX4FS_RW
#define CONFIG_ROMFS_FS 1
#define CONFIG_EXT2_FS 1
#undef  CONFIG_SYSV_FS
#undef  CONFIG_UDF_FS
#undef  CONFIG_UDF_RW
#undef  CONFIG_UFS_FS
#undef  CONFIG_UFS_FS_WRITE

/*
 * Network File Systems
 */
#undef  CONFIG_CODA_FS
#undef  CONFIG_INTERMEZZO_FS
#define CONFIG_NFS_FS 1
#undef  CONFIG_NFS_V3
#undef  CONFIG_ROOT_NFS
#undef  CONFIG_NFSD
#undef  CONFIG_NFSD_V3
#define CONFIG_SUNRPC 1
#define CONFIG_LOCKD 1
#undef  CONFIG_SMB_FS
#undef  CONFIG_NCP_FS
#undef  CONFIG_NCPFS_PACKET_SIGNING
#undef  CONFIG_NCPFS_IOCTL_LOCKING
#undef  CONFIG_NCPFS_STRONG
#undef  CONFIG_NCPFS_NFS_NS
#undef  CONFIG_NCPFS_OS2_NS
#undef  CONFIG_NCPFS_SMALLDOS
#undef  CONFIG_NCPFS_NLS
#undef  CONFIG_NCPFS_EXTRAS
#undef  CONFIG_ZISOFS_FS
#undef  CONFIG_ZLIB_FS_INFLATE

/*
 * Partition Types
 */
#undef  CONFIG_PARTITION_ADVANCED
#define CONFIG_MSDOS_PARTITION 1
#undef  CONFIG_SMB_NLS
#undef  CONFIG_NLS

/*
 * Character devices
 */
#undef  CONFIG_LEDMAN
#undef  CONFIG_VT
#undef  CONFIG_SERIAL
#undef  CONFIG_SERIAL_EXTENDED
#undef  CONFIG_SERIAL_NONSTANDARD
#undef  CONFIG_SERIAL_DSC21
#undef  CONFIG_UNIX98_PTYS

/*
 * I2C support
 */
#undef  CONFIG_I2C

/*
 * Mice
 */
#undef  CONFIG_BUSMOUSE
#undef  CONFIG_MOUSE

/*
 * Joysticks
 */
#undef  CONFIG_INPUT_GAMEPORT
#undef  CONFIG_INPUT_NS558
#undef  CONFIG_INPUT_LIGHTNING
#undef  CONFIG_INPUT_PCIGAME
#undef  CONFIG_INPUT_CS461X
#undef  CONFIG_INPUT_EMU10K1
#undef  CONFIG_INPUT_SERIO
#undef  CONFIG_INPUT_SERPORT

/*
 * Joysticks
 */
#undef  CONFIG_INPUT_ANALOG
#undef  CONFIG_INPUT_A3D
#undef  CONFIG_INPUT_ADI
#undef  CONFIG_INPUT_COBRA
#undef  CONFIG_INPUT_GF2K
#undef  CONFIG_INPUT_GRIP
#undef  CONFIG_INPUT_INTERACT
#undef  CONFIG_INPUT_TMDC
#undef  CONFIG_INPUT_SIDEWINDER
#undef  CONFIG_INPUT_IFORCE_USB
#undef  CONFIG_INPUT_IFORCE_232
#undef  CONFIG_INPUT_WARRIOR
#undef  CONFIG_INPUT_MAGELLAN
#undef  CONFIG_INPUT_SPACEORB
#undef  CONFIG_INPUT_SPACEBALL
#undef  CONFIG_INPUT_STINGER
#undef  CONFIG_INPUT_DB9
#undef  CONFIG_INPUT_GAMECON
#undef  CONFIG_INPUT_TURBOGRAFX
#undef  CONFIG_QIC02_TAPE

/*
 * Watchdog Cards
 */
#undef  CONFIG_WATCHDOG
#undef  CONFIG_INTEL_RNG
#undef  CONFIG_NVRAM
#undef  CONFIG_RTC
#undef  CONFIG_DTLK
#undef  CONFIG_R3964
#undef  CONFIG_APPLICOM

/*
 * Ftape, the floppy tape device driver
 */
#undef  CONFIG_FTAPE
#undef  CONFIG_AGP
#undef  CONFIG_DRM

/*
 * USB support
 */
#undef  CONFIG_USB

/*
 * USB Controllers
 */
#undef  CONFIG_USB_UHCI
#undef  CONFIG_USB_UHCI_ALT
#undef  CONFIG_USB_OHCI

/*
 * USB Device Class drivers
 */
#undef  CONFIG_USB_AUDIO
#undef  CONFIG_USB_BLUETOOTH
#undef  CONFIG_USB_STORAGE
#undef  CONFIG_USB_STORAGE_DEBUG
#undef  CONFIG_USB_STORAGE_DATAFAB
#undef  CONFIG_USB_STORAGE_FREECOM
#undef  CONFIG_USB_STORAGE_ISD200
#undef  CONFIG_USB_STORAGE_DPCM
#undef  CONFIG_USB_STORAGE_HP8200e
#undef  CONFIG_USB_STORAGE_SDDR09
#undef  CONFIG_USB_STORAGE_JUMPSHOT
#undef  CONFIG_USB_ACM
#undef  CONFIG_USB_PRINTER

/*
 * USB Human Interface Devices (HID)
 */
#undef  CONFIG_USB_HID
#undef  CONFIG_USB_HIDDEV
#undef  CONFIG_USB_KBD
#undef  CONFIG_USB_MOUSE
#undef  CONFIG_USB_WACOM

/*
 * USB Imaging devices
 */
#undef  CONFIG_USB_DC2XX
#undef  CONFIG_USB_MDC800
#undef  CONFIG_USB_SCANNER
#undef  CONFIG_USB_MICROTEK
#undef  CONFIG_USB_HPUSBSCSI

/*
 * USB Multimedia devices
 */
#undef  CONFIG_USB_IBMCAM
#undef  CONFIG_USB_OV511
#undef  CONFIG_USB_PWC
#undef  CONFIG_USB_SE401
#undef  CONFIG_USB_DSBR
#undef  CONFIG_USB_DABUSB

/*
 * USB Network adaptors
 */
#undef  CONFIG_USB_PEGASUS
#undef  CONFIG_USB_KAWETH
#undef  CONFIG_USB_CATC
#undef  CONFIG_USB_CDCETHER
#undef  CONFIG_USB_USBNET

/*
 * USB port drivers
 */
#undef  CONFIG_USB_USS720

/*
 * USB Serial Converter support
 */
#undef  CONFIG_USB_SERIAL
#undef  CONFIG_USB_SERIAL_GENERIC
#undef  CONFIG_USB_SERIAL_BELKIN
#undef  CONFIG_USB_SERIAL_WHITEHEAT
#undef  CONFIG_USB_SERIAL_DIGI_ACCELEPORT
#undef  CONFIG_USB_SERIAL_EMPEG
#undef  CONFIG_USB_SERIAL_FTDI_SIO
#undef  CONFIG_USB_SERIAL_VISOR
#undef  CONFIG_USB_SERIAL_IR
#undef  CONFIG_USB_SERIAL_EDGEPORT
#undef  CONFIG_USB_SERIAL_KEYSPAN_PDA
#undef  CONFIG_USB_SERIAL_KEYSPAN
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA28
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA28X
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA28XA
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA28XB
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA19
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA18X
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA19W
#undef  CONFIG_USB_SERIAL_KEYSPAN_USA49W
#undef  CONFIG_USB_SERIAL_MCT_U232
#undef  CONFIG_USB_SERIAL_PL2303
#undef  CONFIG_USB_SERIAL_CYBERJACK
#undef  CONFIG_USB_SERIAL_XIRCOM
#undef  CONFIG_USB_SERIAL_OMNINET

/*
 * USB Miscellaneous drivers
 */
#undef  CONFIG_USB_RIO500

/*
 * I2O device support
 */
#undef  CONFIG_I2O
#undef  CONFIG_I2O_BLOCK
#undef  CONFIG_I2O_LAN
#undef  CONFIG_I2O_SCSI
#undef  CONFIG_I2O_PROC

/*
 * Kernel hacking
 */
#define CONFIG_FRAME_POINTER 1
#undef  CONFIG_REVISIT
#undef  CONFIG_DEBUG_ERRORS
#undef  CONFIG_DEBUG_USER
#undef  CONFIG_DEBUG_INFO
#undef  CONFIG_MAGIC_SYSRQ
#undef  CONFIG_DEBUG_LL
#undef  CONFIG_CONTIGUOUS_PAGE_ALLOC
#undef  CONFIG_MEM_MAP
