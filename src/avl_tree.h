/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the Lesser GNU General Public License, version 3
 * or later ("LGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the Lesser GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */


#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "common_define.h"

typedef struct tagAVLTreeNode {
	void *data;
	struct tagAVLTreeNode *left;
	struct tagAVLTreeNode *right;
	byte balance;
} AVLTreeNode;

typedef int (*DataOpFunc) (void *data, void *args);

typedef struct tagAVLTreeInfo {
	AVLTreeNode *root;
	FreeDataFunc free_data_func;
	CompareFunc compare_func;
} AVLTreeInfo;

#ifdef __cplusplus
extern "C" {
#endif

int avl_tree_init(AVLTreeInfo *tree, FreeDataFunc free_data_func, \
	CompareFunc compare_func);
void avl_tree_destroy(AVLTreeInfo *tree);

int avl_tree_insert(AVLTreeInfo *tree, void *data);
int avl_tree_replace(AVLTreeInfo *tree, void *data);
int avl_tree_delete(AVLTreeInfo *tree, void *data);
void *avl_tree_find(AVLTreeInfo *tree, void *target_data);
void *avl_tree_find_ge(AVLTreeInfo *tree, void *target_data);
int avl_tree_walk(AVLTreeInfo *tree, DataOpFunc data_op_func, void *args);
int avl_tree_count(AVLTreeInfo *tree);
int avl_tree_depth(AVLTreeInfo *tree);
//void avl_tree_print(AVLTreeInfo *tree);

#ifdef __cplusplus
}
#endif

#endif
