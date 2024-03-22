#pragma once

#define POOL_TAG 'rvkU'
#define DRIVER_LOG_PREFIX "[unKover] :: "
#define LOG_MSG(x, ...) DbgPrint((DRIVER_LOG_PREFIX x), __VA_ARGS__)

PDRIVER_OBJECT g_drvObj = NULL;