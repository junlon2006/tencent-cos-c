/**************************************************************************
 * Copyright (C) 2022-2023  Junlon2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **************************************************************************/
#ifndef __TENCENT_OSS_SDK_H__
#define __TENCENT_OSS_SDK_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief push object to tencent OSS
 *
 * @param data              object buffer pointer
 * @param len               object length
 * @param object_name       object name
 * @param bucket_name       bucket name
 * @param region            oss region
 * @param access_key_id     access key id
 * @param access_key_secret access key secret
 * @param token             temporary session token
 *
 * @return int 0 for success, -1 for failed
 */
int tencent_oss_push(const char *data, int len, const char *object_name,
                     const char *bucket_name, const char *region,
                     const char *access_key_id, const char *access_key_secret, const char *token);

#ifdef __cplusplus
}
#endif
#endif  /* __TENCENT_OSS_SDK_H__ */