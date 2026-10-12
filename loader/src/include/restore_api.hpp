#pragma once

namespace linker {

// In a process whose module GOTs were bound to this DSO, point those slots
// back at libc/libdl before unmap. Processes that never bound a slot are skipped.
void RestoreLinkerApiBindings();

}  // namespace linker
