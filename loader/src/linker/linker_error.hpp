#pragma once

namespace linker {

void SetError(const char* msg);
void SetErrorf(const char* fmt, ...);
const char* GetError();

}  // namespace linker
