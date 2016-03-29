package by.psu.arp.common.storage.api;

import java.io.Serializable;

/**
 * Storage interface.
 * <p>
 * Date: Mar 26, 2016
 * </p>
 */
public interface IStorage<T extends Serializable> {

    /**
     * Adds item to storage.
     *
     * @param item item to add
     * @return operation success result
     */
    boolean put(T item);

    /**
     * Gets and then deletes the head of the storage.
     *
     * @return head element
     */
    T poll();
}
