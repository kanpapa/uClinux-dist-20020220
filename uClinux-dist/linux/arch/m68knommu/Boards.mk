# Put definitions for platforms and boards in here.

ifdef CONFIG_M68328
PLATFORM := 68328
ifdef CONFIG_PILOT
BOARD := pilot
endif
endif

ifdef CONFIG_M68EZ328
PLATFORM := 68EZ328
ifdef CONFIG_PILOT
BOARD := PalmV
endif
ifdef CONFIG_UCSIMM
BOARD := ucsimm
endif
ifdef CONFIG_ALMA_ANS
BOARD := alma_ans
endif
ifdef CONFIG_ADS
BOARD := alma_ads
endif
endif

ifdef CONFIG_M68332
PLATFORM := 68332
endif

ifdef CONFIG_M68EN302
PLATFORM := 68EN302
BOARD := generic
endif

ifdef CONFIG_M68360
PLATFORM := 68360
ifdef CONFIG_UCQUICC
BOARD := uCquicc
endif
ifdef CONFIG_SED_SIOS
BOARD := sed_sios
endif
endif

ifdef CONFIG_M5204
PLATFORM := 5204
BOARD := SBC5204
endif

ifdef CONFIG_M5206
PLATFORM := 5206
BOARD := ARNEWSH
endif

ifdef CONFIG_M5206e
PLATFORM := 5206e
ifdef CONFIG_CADRE3
BOARD := CADRE3
endif
ifdef CONFIG_ELITE
BOARD := eLITE
endif
ifdef CONFIG_NETtel
BOARD := NETtel
endif
ifdef CONFIG_TELOS
BOARD := toolvox
endif
ifdef CONFIG_CFV240
BOARD := CFV240
endif
endif

ifdef CONFIG_M5272
PLATFORM := 5272
ifdef CONFIG_MOTOROLA
BOARD := MOTOROLA
endif
ifdef CONFIG_NETtel
BOARD := NETtel
endif
ifdef CONFIG_MARCONINAP
BOARD := NAP
endif
endif

ifdef CONFIG_M5307
PLATFORM := 5307
ifdef CONFIG_ARNEWSH
BOARD := ARNEWSH
endif
ifdef CONFIG_NETtel
BOARD := NETtel
endif
ifdef CONFIG_eLIA
BOARD := eLIA
endif
ifdef CONFIG_DISKtel
BOARD := DISKtel
endif
ifdef CONFIG_SECUREEDGEMP3
BOARD := MP3
endif
ifdef CONFIG_CADRE3
BOARD := CADRE3
endif
ifdef CONFIG_CLEOPATRA
BOARD := CLEOPATRA
endif
endif

ifdef CONFIG_M5407
PLATFORM := 5407
ifdef CONFIG_MOTOROLA
BOARD := MOTOROLA
endif
ifdef CONFIG_CLEOPATRA
BOARD := CLEOPATRA
endif
endif