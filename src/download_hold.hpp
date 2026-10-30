#pragma once

#include "kernauth.hpp"

#include <filesystem>

namespace kernauth {

/**
 * Keep a successful download in memory and wipe it.
 * Does not open output_path. A failed download or an inactive license writes nothing.
 */
int release_download(bool active, DownloadResult& file, const std::filesystem::path& output_path);

}  // namespace kernauth
