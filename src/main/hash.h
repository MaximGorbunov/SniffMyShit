#ifndef SNIFFMYSHIT_SRC_MAIN_HASH_H_
#define SNIFFMYSHIT_SRC_MAIN_HASH_H_

namespace sniff_my_shit {
template<class T>
inline void hash_combine(std::size_t &s, const T &v) {
  std::hash<T> h;
  s ^= h(v) + 0x9e3779b9 + (s << 6) + (s >> 2);
}
}
#endif //SNIFFMYSHIT_SRC_MAIN_HASH_H_
