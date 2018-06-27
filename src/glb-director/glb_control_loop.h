struct glb_fwd_config_ctx *load_glb_fwd_config(void);
int main_loop_control(__rte_unused void *arg);

extern struct glb_processor_ctx *glb_lcore_contexts[RTE_MAX_LCORE];
extern struct rte_mempool *glb_processor_msg_pool;

void signal_handler(int signum);
