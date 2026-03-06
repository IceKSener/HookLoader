#ifndef HOOKDLL_HPP
#define HOOKDLL_HPP

#include <windows.h>

#include "RegForm.hpp"

BOOL SendRequestAndReceive(const RegRequest& req, RegResponse& res);

#endif // HOOKDLL_HPP