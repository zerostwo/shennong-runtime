#!/usr/bin/env Rscript

parse_responses <- function(lines) {
  lapply(lines[nzchar(lines)], jsonlite::fromJSON, simplifyVector = FALSE)
}

smoke_server <- function(server, expected_tools) {
  requests <- c(
    jsonlite::toJSON(list(
      jsonrpc = "2.0", id = 1L, method = "initialize",
      params = list(
        protocolVersion = "2025-11-25",
        capabilities = list(),
        clientInfo = list(name = "shennong-runtime-build", version = "1")
      )
    ), auto_unbox = TRUE),
    jsonlite::toJSON(list(
      jsonrpc = "2.0", method = "notifications/initialized", params = list()
    ), auto_unbox = TRUE),
    jsonlite::toJSON(list(
      jsonrpc = "2.0", id = 2L, method = "tools/list", params = list()
    ), auto_unbox = TRUE)
  )
  input <- textConnection(requests, open = "r")
  output <- textConnection("captured", open = "w", local = TRUE)
  on.exit(close(input), add = TRUE)
  server(input, output)
  close(output)
  responses <- parse_responses(captured)
  initialized <- responses[[which(vapply(responses, function(x) identical(x$id, 1L), logical(1)))]]
  listed <- responses[[which(vapply(responses, function(x) identical(x$id, 2L), logical(1)))]]
  stopifnot(identical(initialized$result$protocolVersion, "2025-11-25"))
  names <- vapply(listed$result$tools, `[[`, character(1), "name")
  stopifnot(setequal(names, expected_tools))
  stopifnot(all(vapply(
    listed$result$tools,
    function(tool) isTRUE(tool$annotations$readOnlyHint),
    logical(1)
  )))
}

stopifnot(
  getRversion() >= "4.6.0",
  identical(as.character(utils::packageVersion("Shennong")), "0.2.0.9000"),
  identical(as.character(utils::packageVersion("ShennongData")), "0.2.0")
)

config <- Shennong::sn_mcp_server_config()
stopifnot(
  identical(config$transport, "stdio"),
  file.exists(config$command),
  dir.exists(Shennong::sn_get_codex_skill_path("package_skills"))
)

smoke_server(
  Shennong::sn_mcp_server,
  c("list_methods", "method_status", "function_help", "workflow_guide", "package_info")
)
smoke_server(
  ShennongData::sn_mcp_serve,
  c(
    "check_compatibility", "list_resources", "inspect_resource",
    "resolve_features", "plan_query", "fetch_data"
  )
)

installed_skills <- Sys.getenv(
  "SHENNONG_AGENT_SKILLS_DIR",
  unset = "/opt/shennong/agent/skills"
)
stopifnot(
  file.exists(file.path(installed_skills, "use-shennong-mcp", "SKILL.md")),
  file.exists(file.path(installed_skills, "use-shennong-single-cell-workflows", "SKILL.md")),
  file.exists(file.path(installed_skills, "shennong-data", "SKILL.md"))
)

manifest <- list(
  schema = "shennong.dev/runtime-r-toolchain/v1",
  r = R.version.string,
  packages = list(
    Shennong = as.character(utils::packageVersion("Shennong")),
    ShennongData = as.character(utils::packageVersion("ShennongData"))
  ),
  mcp = list(
    Shennong = c("list_methods", "method_status", "function_help", "workflow_guide", "package_info"),
    ShennongData = c(
      "check_compatibility", "list_resources", "inspect_resource",
      "resolve_features", "plan_query", "fetch_data"
    )
  ),
  skills = sort(list.files(installed_skills))
)
manifest_path <- Sys.getenv(
  "SHENNONG_R_TOOLCHAIN_MANIFEST",
  unset = "/opt/shennong/runtime-r-toolchain.json"
)
stopifnot(dir.exists(dirname(manifest_path)))
jsonlite::write_json(
  manifest,
  manifest_path,
  auto_unbox = TRUE,
  pretty = TRUE
)
