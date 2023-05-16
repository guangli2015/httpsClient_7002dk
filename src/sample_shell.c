#include <zephyr/zephyr.h>
#include <zephyr/shell/shell.h>
#include <zephyr/init.h>

K_SEM_DEFINE(wifi_ready, 0, 1);

static int cmd_sample_mqtt_start(const struct shell *sh, size_t argc,
			    char *argv[])
{
	k_sem_give(&wifi_ready);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sample_commands,
	SHELL_CMD(https_start, NULL, "Start sample", cmd_sample_mqtt_start),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sample, &sample_commands, "Sample commands", NULL);

static int sample_shell_init(const struct device *unused)
{
	ARG_UNUSED(unused);
	return 0;
}

SYS_INIT(sample_shell_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
