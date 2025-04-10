#include<iostream>
#include<functional>

class Guard {
	using Func = std::function<void()>;
public:
	explicit Guard(const std::function<void()>& func) :func_(func),active_(true) {
	}

	Guard(const Guard&) = delete;

	Guard& operator=(const Guard&) = delete;

	Guard(Guard&& other) noexcept : func_(std::move(other.func_)), active_(other.active_.exchange(false)) {
	}

	Guard& operator=(Guard&& other) noexcept {
		if (this != &other) {
			if (active_ && func_) {
				func_();
			}
			func_ = std::move(other.func_);
			active_ = other.active_.exchange(false);
		}
		return *this;
	}

	~Guard() {
		if (active_ && func_) {
			func_();
		}
	}
private:
	Func func_;
	std::atomic<bool> active_{false};
};

int main() {
	{
		Guard g([]() {
			std::cout << "Guard destructor called" << std::endl;
			});
		std::cout << "Inside main" << std::endl;
		Guard g2(std::move(g));
	}
	return 0;
}
