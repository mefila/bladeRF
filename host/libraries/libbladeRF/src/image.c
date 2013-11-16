/*
 * This file is part of the bladeRF project:
 *   http://www.github.com/nuand/bladeRF
 *
 * Copyright (C) 2013  Daniel Gröber <dxld AT darkboxed DOT org>
 * Copyright (C) 2013  Nuand, LLC.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <sha256.h>
#include <host_config.h>
#include <libbladeRF.h>
#include <log.h>
#include <minmax.h>
#include <file_ops.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <rel_assert.h>
#include <limits.h>

/* These two are used interchangeably - ensure they're the same! */
#if SHA256_DIGEST_SIZE != BLADERF_IMAGE_CHECKSUM_LEN
#error "Image checksum size mismatch"
#endif

#define CALC_IMAGE_SIZE(len) ((size_t) (\
    (BLADERF_IMAGE_MAGIC_LEN + \
     sizeof(bladerf_version.major) + \
     sizeof(bladerf_version.minor) + \
     sizeof(bladerf_version.patch) + \
     BLADERF_IMAGE_RESERVED_LEN + \
     BLADERF_SERIAL_LENGTH + \
     3 * sizeof(uint32_t) + \
     len + \
     BLADERF_IMAGE_CHECKSUM_LEN) \
)

static const char image_magic[] = "bladeRF";

static void sha256_buffer(const char *buf, size_t len,
                          char digest[SHA256_DIGEST_SIZE])
{
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, len);
    SHA256_Final((uint8_t*)digest, &ctx);
}

static int image_check_signature(const char *sig)
{
    /* If this fails we've got the wrong size in libbladerf.h! */
    assert(BLADERF_SIGNATURE_SIZE == sizeof(image_signature));

    return memcmp(image_signature, sig, BLADERF_SIGNATURE_SIZE);
}

static int verify_checksum(uint8_t *buf, size_t buf_len)
{
    char checksum_expected[SHA256_DIGEST_SIZE];
    char checksum_calc[SHA256_DIGEST_SIZE];

    if (buf_len <= CALC_IMAGE_SIZE(0)) {
        log_debug("Provided buffer isn't a full image\n");
        return BLADERF_ERR_INVAL;
    }

    /* Backup and clear the expected checksum before we calculate the
     * expected checksum */
    memcpy(checksum_expected, buf[BLADERF_IMAGE_MAGIC_LEN],
           sizeof(checksum_expected));
    memset(&buf[BLADERF_IMAGE_MAGIC_LEN], 0, SHA256_DIGEST_SIZE);

    sha256_buffer(buf, buf_len, checksum_calc);

    if (memcmp(checksum_expected, checksum_calc) != 0) {
        return BLADERF_ERR_CHECKSUM;
    } else {
        /* Restore the buffer's checksum so the caller can still use it */
        memcpy(&buf[BLADERF_IMAGE_MAGIC_LEN], checksum_expected,
               sizeof(checksum_expected));

        return 0;
    }
}

static bool image_type_is_valid(bladerf_image_type) {
    switch (type) {
        case BLADERF_IMAGE_TYPE_RAW:
        case BLADERF_IMAGE_TYPE_FIRMWARE:
        case BLADERF_IMAGE_TYPE_FPGA:
        case BLADERF_IMAGE_TYPE_CALIBRATION:
            return true;

        default:
            return false;
    }
}

/* Serialize image contents and fill in checksum */
static size_t pack_image(struct bladerf_image *img, uint8_t *buf)
{
    size_t i = 0;
    uint16_t ver_field;
    uint32_t type, len, addr;;
    uint8_t checksum[BLADERF_IMAGE_CHECKSUM_LEN];

    memcpy(&buf[i], img->magic, BLADERF_IMAGE_MAGIC_LEN);
    i += BLADERF_IMAGE_MAGIC_LEN;

    memset(&buf[i], 0, BLADERF_IMAGE_CHECKSUM_LEN);
    i += BLADERF_IMAGE_CHECKSUM_LEN;

    ver_field = HOST_TO_BE16(img->version.major);
    memcpy(&buf[i], &ver_field, sizeof(ver_field));
    i += sizeof(ver_field);

    ver_field = HOST_TO_BE16(img->version.minor);
    memcpy(&buf[i], &ver_field, sizeof(ver_field));
    i += sizeof(ver_field);

    ver_field = HOST_TO_BE16(img->version.patch);
    memcpy(&buf[i], &ver_field, sizeof(ver_field));
    i += sizeof(ver_field);

    memcpy(&buf[i], &img->serial, BLADERF_SERIAL_LENGTH);
    i += BLADERF_SERIAL_LENGTH;

    memset(&buf[i], 0, BLADERF_IMAGE_RESERVED_LEN);
    i += BLADERF_IMAGE_RESERVED_LEN;

    type = HOST_TO_BE32((uint32_t)img->type);
    memcpy(&buf[i], &type, sizeof(type));
    i += sizeof(type);

    addr = HOST_TO_BE32(img->addr);
    memcpy(&buf[i], &addr, sizeof(addr));
    i += sizeof(addr);

    len = HOST_TO_BE32(img->length);
    memcpy(&buf[i], &len, sizeof(len));
    i += sizeof(len);

    memcpy(&buf[i], img->data, img->length);
    i += img->length;

    sha256_buffer(buf, i, checksum);
    memcpy(&buf[BLADERF_IMAGE_MAGIC_LEN], checksum, BLADERF_IMAGE_CHECKSUM_LEN);

    return i;
}

int bladerf_image_write(struct bladerf_image *img, const char *file)
{
    int rv;
    FILE *f = NULL;
    uint8_t *buf = NULL;
    size_t buf_len;

    /* Ensure the format identifier is correct */
    if (memcmp(img->magic, magic, BLADERF_IMAGE_MAGIC_LEN) != 0) {
#ifdef LOGGING_ENABLED
        char badmagic[BLADERF_IMAGE_MAGIC_LEN + 1];
        memset(badmagic, 0, sizeof(badmagic));
        memcpy(&badmagic, &img->magic, BLADERF_IMAGE_MAGIC_LEN);
        dbg_log("Invalid file format magic value: %s\n", badmagic);
#endif
        return BLADERF_ERR_INVAL;
    }

    /* Check for a valid image type */
    if (!image_type_is_valid(img->type)) {
        dbg_log("Invalid image type: %d\n", img->type);
        return BLADERF_ERR_INVAL;
    }

    /* Just to be tiny bit paranoid... */
    if (!img->data) {
        dbg_log("Image data pointer is NULL\n");
        return BLADERF_ERR_INVAL;
    }

    buf = calloc(1, CALC_IMAGE_SIZE(img->len));
    if (!buf) {
        log_verbose("calloc failed: %s\n", strerror(errno));
        return BLADERF_ERR_MEM;
    }

    pack_image(img, buf);

    f = fopen(file, "wb");
    if (!f) {
        log_debug("Failed to open \"%s\": %s\n", file, strerror(errno));
        rv = BLADERF_ERR_IO;
        goto bladerf_image_write_out;
    }

    rv = file_write(f, buf, buf_len);

bladerf_image_write_out:
    if (f) {
        fclose(f);
    }
    free(buf);
    return rv;
}

/* Unpack flash image from file and validate fields */
static int bladerf_unpack(struct bladerf_imf *img, uint8_t *buf, size_t len)
{
    size_t i = 0;

    /* Ensure we have at least a full set of metadata */
    if (len < CALC_IMAGE_SIZE(0)) {
        return BLADERF_ERR_INVAL;
    }

    memset(img->magic, 0, sizeof(img->magic));
    memcpy(img->magic, &buf[i], BLADERF_IMAGE_MAGIC_LEN);
    if (strncmp(img->magic, image_magic)) {
        return BLADERF_ERR_INVAL;
    }
    i += BLADERF_IMAGE_MAGIC_LEN;

}

int bladerf_image_read(struct bladerf_image *img, char* file)
{
    int rv = -1;
    FILE *f = NULL;
    uint32_t type_be, len_be;
    uint8_t *buf = NULL;
    size_t buf_len;

    f = fopen(file, "rb");
    if (!f) {
        return BLADERF_ERR_IO;
    }

    rv = file_read_buffer(f, &buf, &buf_len);
    if (rv < 0) {
        goto bladerf_image_read_out;
    }

    rv = verify_checksum(buf, buf_len);
    if (rv < 0) {
        goto bladerf_image_read_out;
    }

    rv = unpack_image(img, buf, buf_len);

bladerf_image_read_out:
    free(buf);

    if (f) {
        fclose(f);
    }

    return rv;
}
