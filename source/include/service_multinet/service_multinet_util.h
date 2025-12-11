/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2015] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/
#ifndef MNET_UTIL_H
#define MNET_UTIL_H

typedef struct listItem {
    struct listItem* prev;
    struct listItem* next;

    void* data;
} ListItem, *PListItem;

typedef struct list {
    PListItem first;
    PListItem last;

    int count;
} List, *PList;

typedef struct listIterator {
    PList list;
    PListItem current;
    int bGiven;
} ListIterator, *PListIterator;

/**
* @brief Add an item to a linked list.
*
* @param[in,out] list - Pointer to the List structure.
* @param[in] itemData - Pointer to the data to add to the list.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int addToList(PList list, void* itemData);

/**
* @brief Add an item to a linked list with memory allocation.
*
* @param[in,out] list - Pointer to the List structure.
* @param[in] dataSize - Size in bytes of the data to allocate and add.
*
* @return Pointer to the allocated data.
* @retval pointer to allocated data on success
* @retval NULL on failure.
*
*/
void* addAndAlloc(PList list, int dataSize);

/**
* @brief Remove an item from a linked list.
*
* @param[in,out] list - Pointer to the List structure.
* @param[in] item - Pointer to the ListItem to remove.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int removeFromList(PList list, PListItem item);

/**
* @brief Clear all items from a linked list.
*
* @param[in,out] list - Pointer to the List structure to clear.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int clearList(PList list);

/**
* @brief Get the number of items in a linked list.
*
* @param[in] list - Pointer to the List structure.
*
* @return The number of items in the list.
*
*/
int listSize(PList list);

/**
* @brief Initialize an iterator for a linked list.
*
* @param[in] list - Pointer to the List structure to iterate.
* @param[out] iterator - Pointer to the ListIterator structure to initialize.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int initIterator(PList list, PListIterator iterator);

//int copyIterator(PListIterator to, PListIterator from);

/**
* @brief Get the next item from a list iterator.
*
* @param[in,out] iterator - Pointer to the ListIterator structure.
*
* @return Pointer to the next ListItem
* @retval pointer to next item on success.
* @retval NULL if no more items.
*
*/
PListItem getNext(PListIterator iterator);

/**
* @brief Get the current item from a list iterator.
*
* @param[in] iterator - Pointer to the ListIterator structure.
*
* @return Pointer to the current ListItem
* @retval pointer to current item on success.
* @retval NULL if no current item.
*
*/
PListItem getCurrent(PListIterator iterator);

/**
* @brief Remove the current item from a list iterator.
*
* @param[in,out] iterator - Pointer to the ListIterator structure.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int removeCurrent(PListIterator iterator);

#endif
