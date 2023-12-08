/*
 * Copyright (c) 2023 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_OBSERVABLE_HPP
#define BABELTRACE_CPP_COMMON_BT2C_OBSERVABLE_HPP

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <utility>
#include <vector>

#include "common/assert.h"

namespace bt2c {

/*
 * An implementation of the observer pattern.
 *
 * Instantiate an observable with:
 *
 *     Observable<Args> myObservable;
 *
 * where `Args` is the parameter type(s) of the data passed from the
 * entity notifying the observer to the observer callbacks.
 *
 * Attach an observer with the attach() method:
 *
 *     auto token = myObservable.attach([](Args...) {
 *         // Do something
 *     });
 *
 * attach() returns a token (`Token` instance) which identifies this
 * specific observer within the observable. The destructor of the token
 * detaches the observer from the observable.
 *
 * Notify all the observers with the notify() method:
 *
 *    myObservable.notify(args);
 */
template <typename... Args>
class Observable
{
private:
    using _TokenId = std::uint64_t;
    using _ThisObservable = Observable<Args...>;

    /* Type of user callback of an observer */
    using _ObserverFunc = std::function<void(Args...)>;

public:
    /*
     * A token, identified with a unique ID, is an observer handle
     * within this observable. On destruction, the token detaches the
     * observer from the observable.
     */
    class Token
    {
        friend class Observable;

    private:
        explicit Token(_ThisObservable& observable, const _TokenId tokenId) noexcept :
            _mObservable {&observable}, _mTokenId(tokenId)
        {
        }

    public:
        ~Token()
        {
            if (_mTokenId != _invalidTokenId) {
                _mObservable->_detach(_mTokenId);
            }
        }

        Token(const Token&) = delete;

        Token(Token&& other) noexcept :
            _mObservable {other._mObservable}, _mTokenId {other._mTokenId}
        {
            other._mTokenId = _invalidTokenId;
        }

        Token& operator=(const Token&) = delete;

        Token& operator=(Token&& other) noexcept
        {
            _mObservable = other._mObservable;
            _mTokenId = other._mTokenId;
            other._mTokenId = _invalidTokenId;
        }

    private:
        static constexpr _TokenId _invalidTokenId = std::numeric_limits<_TokenId>::max();
        _ThisObservable *_mObservable;
        _TokenId _mTokenId;
    };

public:
    Observable() = default;
    Observable(const Observable&) = delete;
    Observable(Observable&&) = default;
    Observable& operator=(const Observable&) = delete;
    Observable& operator=(Observable&&) = default;

    /*
     * Attaches an observer using the user callback `func` to this
     * observable, returning a corresponding token.
     */
    Token attach(_ObserverFunc func)
    {
        const auto tokenId = _mNextTokenId;

        ++_mNextTokenId;
        _mObservers.emplace_back(tokenId, std::move(func));
        return Token {*this, tokenId};
    }

    /*
     * Notifies all the managed observers, passing `args` to their user
     * callback.
     */
    void notify(Args... args)
    {
        for (auto& observer : _mObservers) {
            observer.func(std::forward<Args>(args)...);
        }
    }

private:
    /* Element type of `_mObservers` */
    struct _Observer
    {
        _Observer(const _TokenId tokenIdParam, _ObserverFunc funcParam) :
            tokenId {tokenIdParam}, func {std::move(funcParam)}
        {
        }

        _TokenId tokenId;
        _ObserverFunc func;
    };

    /*
     * Removes the observer having the token ID `tokenId` from this
     * observable.
     */
    void _detach(const _TokenId tokenId)
    {
        const auto it =
            std::remove_if(_mObservers.begin(), _mObservers.end(), [tokenId](_Observer& obs) {
                return obs.tokenId == tokenId;
            });

        BT_ASSERT(_mObservers.end() - it == 1);
        _mObservers.erase(it, _mObservers.end());
    }

    /* Next token ID to hand out */
    _TokenId _mNextTokenId = 0;

    /* List of observers */
    mutable std::vector<_Observer> _mObservers;
};

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_OBSERVABLE_HPP */
