#ifndef SNIFFMYSHIT_SRC_MAIN_HANDLER_H_
#define SNIFFMYSHIT_SRC_MAIN_HANDLER_H_
#include <memory>
#include <TcpReassembly.h>

namespace SniffMyShit {
struct Data {
  uint32_t type;
  void *payload;
};

class Handler {
 public:
  explicit Handler(std::unique_ptr<Handler> next_) : next_(std::move(next_)) {}
  virtual ~Handler() = default;
  virtual void handle(std::unique_ptr<Data> data) = 0;
  void pass_next(std::unique_ptr<Data> data) {
    if (next_ != nullptr) {
      next_->handle(std::move(data));
    }
  }

  virtual void connection_closed(const pcpp::ConnectionData &connectionData) {
    if (next_ != nullptr) {
      next_->connection_closed(connectionData);
    }
  };
 protected:
  const std::unique_ptr<Handler> next_;
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_HANDLER_H_
