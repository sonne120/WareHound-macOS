#pragma once
#include <stdint.h>
#include <vector>

void StartPipeWriter();
void StopPipeWriter();
void PushToPipe(const uint8_t* data, int length);

void SetPipeLinkType(int dlt);
