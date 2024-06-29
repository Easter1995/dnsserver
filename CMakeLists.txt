project(DNSSERVER)
aux_source_directory(./src SRC)
aux_source_directory(. SRC_CUR)
include_directories(include)
add_executable(DNSSERVER ${SRC} ${SRC_CUR})
# 添加 ws2_32 库链接
target_link_libraries(DNSSERVER ws2_32)