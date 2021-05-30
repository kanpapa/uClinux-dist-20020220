#ifndef __V850_DMA_H__
#define __V850_DMA_H__

/* What should this be?  */
#define MAX_DMA_ADDRESS	0xFFFFFFFF

/* reserve a DMA channel */
extern int request_dma (unsigned int dmanr, const char * device_id);
/* release it again */
extern void free_dma (unsigned int dmanr);

#define isa_dma_bridge_buggy    (0)

#endif /* __V850_DMA_H__ */
