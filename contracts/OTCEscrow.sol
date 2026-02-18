// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

contract OTCEscrow {
    enum TradeState {
        NONE,
        CREATED,
        SETTLED,
        REFUNDED
    }

    struct Trade {
        address buyer;
        address seller;
        string baseAsset;
        string quoteAsset;
        uint256 baseAmountAtomic;
        uint256 quoteAmountAtomic;
        uint256 timeoutAt;
        TradeState state;
        bytes32 escrowTradeRef;
    }

    mapping(string => Trade) private _trades;

    event TradeCreated(
        string tradeId,
        bytes32 escrowTradeRef,
        address buyer,
        address seller,
        address actor
    );
    event TradeSettled(string tradeId, bytes32 escrowTradeRef, address actor);
    event TradeRefunded(string tradeId, bytes32 escrowTradeRef, address actor);

    function createTrade(
        string calldata tradeId,
        address buyer,
        address seller,
        string calldata baseAsset,
        string calldata quoteAsset,
        uint256 baseAmountAtomic,
        uint256 quoteAmountAtomic,
        uint256 timeoutAt
    ) external returns (bytes32 escrowTradeRef) {
        require(bytes(tradeId).length > 0, "invalid_trade_id");
        require(buyer != address(0) && seller != address(0), "invalid_party");
        require(baseAmountAtomic > 0 && quoteAmountAtomic > 0, "invalid_amount");
        require(timeoutAt > block.timestamp, "invalid_timeout");

        Trade storage trade = _trades[tradeId];
        require(trade.state == TradeState.NONE, "trade_exists");

        escrowTradeRef = keccak256(
            abi.encodePacked(
                block.chainid,
                tradeId,
                buyer,
                seller,
                baseAsset,
                quoteAsset,
                baseAmountAtomic,
                quoteAmountAtomic,
                timeoutAt
            )
        );

        trade.buyer = buyer;
        trade.seller = seller;
        trade.baseAsset = baseAsset;
        trade.quoteAsset = quoteAsset;
        trade.baseAmountAtomic = baseAmountAtomic;
        trade.quoteAmountAtomic = quoteAmountAtomic;
        trade.timeoutAt = timeoutAt;
        trade.state = TradeState.CREATED;
        trade.escrowTradeRef = escrowTradeRef;

        emit TradeCreated(tradeId, escrowTradeRef, buyer, seller, msg.sender);
    }

    function settleTrade(string calldata tradeId) external {
        Trade storage trade = _trades[tradeId];
        require(trade.state == TradeState.CREATED, "invalid_state");
        require(msg.sender == trade.buyer || msg.sender == trade.seller, "unauthorized");

        trade.state = TradeState.SETTLED;
        emit TradeSettled(tradeId, trade.escrowTradeRef, msg.sender);
    }

    function refundTrade(string calldata tradeId) external {
        Trade storage trade = _trades[tradeId];
        require(trade.state == TradeState.CREATED, "invalid_state");
        require(block.timestamp >= trade.timeoutAt, "timeout_not_reached");
        require(msg.sender == trade.buyer || msg.sender == trade.seller, "unauthorized");

        trade.state = TradeState.REFUNDED;
        emit TradeRefunded(tradeId, trade.escrowTradeRef, msg.sender);
    }

    function getTrade(string calldata tradeId)
        external
        view
        returns (
            address buyer,
            address seller,
            string memory baseAsset,
            string memory quoteAsset,
            uint256 baseAmountAtomic,
            uint256 quoteAmountAtomic,
            uint256 timeoutAt,
            uint8 state,
            bytes32 escrowTradeRef
        )
    {
        Trade storage trade = _trades[tradeId];
        return (
            trade.buyer,
            trade.seller,
            trade.baseAsset,
            trade.quoteAsset,
            trade.baseAmountAtomic,
            trade.quoteAmountAtomic,
            trade.timeoutAt,
            uint8(trade.state),
            trade.escrowTradeRef
        );
    }

    function getTradeState(string calldata tradeId) external view returns (uint8) {
        return uint8(_trades[tradeId].state);
    }
}
