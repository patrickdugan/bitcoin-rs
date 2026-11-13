#include "command.hpp"
#include "yqueue.hpp"
#include <cstdint>
#include <cstdio>

int main() {
    zmq::yqueue_t<zmq::command_t, 17> queues[8];
    const std::size_t required = alignof(zmq::command_t);
    bool aligned = true;
    std::printf("{\"required_alignment\":%zu,\"observed\":[", required);
    for (std::size_t index = 0; index != 8; ++index) {
        queues[index].push();
        volatile std::uintptr_t observed =
            reinterpret_cast<std::uintptr_t>(&queues[index].back());
        const auto address = static_cast<unsigned long long>(observed);
        const auto remainder = address % required;
        aligned = aligned && remainder == 0;
        std::printf("%s{\"address\":%llu,\"remainder\":%llu}",
                    index ? "," : "", address, remainder);
    }
    std::printf("],\"aligned\":%s}\n", aligned ? "true" : "false");
    return aligned ? 0 : 1;
}
