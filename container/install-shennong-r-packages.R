#!/usr/bin/env Rscript

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2L) {
  stop("usage: install-shennong-r-packages.R SHENNONG_SOURCE SHENNONG_DATA_SOURCE")
}

repos <- c(CRAN = "https://cloud.r-project.org")
options(repos = repos, timeout = 600)

hard_dependencies <- c(
  "cli", "curl", "digest", "dplyr", "ggplot2", "glue", "jsonlite", "logger",
  "rlang", "tictoc", "RColorBrewer", "stringr", "tibble", "S7", "httr2"
)
missing <- hard_dependencies[
  !vapply(hard_dependencies, requireNamespace, logical(1), quietly = TRUE)
]
if (length(missing)) {
  install.packages(
    missing,
    dependencies = c("Depends", "Imports", "LinkingTo"),
    Ncpus = max(1L, min(4L, parallel::detectCores(logical = FALSE))),
    clean = TRUE
  )
}

install_local <- function(path) {
  status <- system2(
    file.path(R.home("bin"), "R"),
    c("CMD", "INSTALL", "--no-multiarch", "--with-keep.source", shQuote(path))
  )
  if (!identical(status, 0L)) stop("R CMD INSTALL failed for ", path)
}

# Shennong declares ShennongData only as an optional integration. Installing the
# data client first still guarantees that the unified Runtime exposes the full
# platform pair from one immutable image.
install_local(normalizePath(args[[2L]], mustWork = TRUE))
install_local(normalizePath(args[[1L]], mustWork = TRUE))

expected <- c(Shennong = "0.2.0.9000", ShennongData = "0.2.0.9000")
observed <- vapply(names(expected), function(package) {
  if (!requireNamespace(package, quietly = TRUE)) stop(package, " is unavailable")
  as.character(utils::packageVersion(package))
}, character(1))
if (!identical(observed, expected)) {
  stop("unexpected Shennong package versions: ", paste(names(observed), observed, collapse = ", "))
}
