/**
* Copyright (C) 2008 Seapeak.Xu / xvhfeng@gmail.com
*
* FastLib may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastLib source kit.
* Please visit the FastLib Home Page http://www.csource.org/ for more detail.
**/

#ifndef IO_OPT_H_
#define IO_OPT_H_

#ifndef MAX_PATH_SIZE
#define MAX_PATH_SIZE 1024
#endif

/*
 * create the dir by full dir_path
 * parameters:
 * 				path : the dir full path
 * 				mode : the mode for mkdir
 * return:
 * 				0:create dir is success
 * 				-1 : get current path is error;
 * 				-2 : change dir is error;
 * 				-3 : malloc memory to subfolder is error
 * 				-4 : create dir is error;
 */
int mkdir_by_cascading(const char *path, mode_t mode);

/*
 * check the first parameter is the dir
 * parameters:
 * 				path : the dir full path
 * return:
 * 				0:the path is dir
 * 				not 0: the path is not dir
 */
int is_dir(const char *path);


#endif /* IO_OPT_H_ */
