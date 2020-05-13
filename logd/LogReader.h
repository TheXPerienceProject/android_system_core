/*
 * Copyright (C) 2012-2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sysutils/SocketListener.h>

#include "LogReaderList.h"
#include "LogReaderThread.h"

#define LOGD_SNDTIMEO 32

class LogBuffer;

class LogReader : public SocketListener {
  public:
    explicit LogReader(LogBuffer* logbuf, LogReaderList* reader_list);

    LogBuffer* log_buffer() const { return log_buffer_; }

  protected:
    virtual bool onDataAvailable(SocketClient* cli);

  private:
    static int getLogSocket();

    void doSocketDelete(SocketClient* cli);

    LogBuffer* log_buffer_;
    LogReaderList* reader_list_;
};
