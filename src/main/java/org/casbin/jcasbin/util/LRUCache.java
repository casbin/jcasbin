// Copyright 2022 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.jcasbin.util;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Yixiang Zhao (@seriouszyx)
 **/
public class LRUCache<K, V> {
    static class Node<T, U> {
        T key;
        U value;
        Node<T, U> prev;
        Node<T, U> next;

        public Node() {
        }
        public Node(T key, U value, Node<T, U> prev, Node<T, U> next){
            this.key = key;
            this.value = value;
            this.prev = prev;
            this.next = next;
        }
    }

    private final int capacity;
    private final Map<K, Node<K, V>> m;
    private final Node<K, V> head;
    private final Node<K, V> tail;

    public LRUCache(int capacity) {
        this.capacity = capacity;
        this.m = new HashMap<>();

        Node<K, V> head = new Node<>();
        Node<K, V> tail = new Node<>();

        head.next = tail;
        tail.prev = head;

        this.head = head;
        this.tail = tail;
    }

    private void remove(Node<K, V> n, boolean listOnly) {
        if (!listOnly) {
            this.m.remove(n.key);
        }
        n.prev.next = n.next;
        n.next.prev = n.prev;
    }

    private void add(Node<K, V> n, boolean listOnly) {
        if (!listOnly) {
            this.m.put(n.key, n);
        }
        Node<K, V> headNext = this.head.next;
        this.head.next = n;
        headNext.prev = n;
        n.next = headNext;
        n.prev = this.head;
    }

    private void moveToHead(Node<K, V> n) {
        remove(n, true);
        add(n, true);
    }

    public V get(K key) {
        Node<K, V> node = this.m.get(key);
        if (node != null) {
            moveToHead(node);
            return node.value;
        } else {
            return null;
        }
    }

    public void put(K key, V value) {
        Node<K, V> node = this.m.get(key);
        if (node != null) {
            remove(node, false);
        } else {
            node = new Node<>(key, value, null, null);
            if (this.m.size() >= this.capacity) {
                remove(this.tail.prev, false);
            }
        }
        add(node, false);
    }
}
