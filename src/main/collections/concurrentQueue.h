#ifndef SNIFFMYSHIT_SRC_MAIN_COLLECTIONS_CONCURRENTQUEUE_H_
#define SNIFFMYSHIT_SRC_MAIN_COLLECTIONS_CONCURRENTQUEUE_H_
#include <queue>
#include <mutex>

namespace SniffMyShit {
template<typename T>
class ConcurrentQueue {
 private:
  std::queue<T> queue_;
  std::mutex mutex;
 public:
  ConcurrentQueue() : queue_() {}
  void push(const T &value) {
    std::lock_guard<std::mutex> lock(mutex);
    queue_.push(value);
  }

  bool try_pop(T &val) {
    std::lock_guard<std::mutex> lock(mutex);
    if (!queue_.empty()) {
      val = queue_.front();
      queue_.pop();
      return true;
    }
    return false;
  }
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_COLLECTIONS_CONCURRENTQUEUE_H_