package net.ladenthin.bitcoinaddressfinder;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class OpenCLGridResultTest {

    @Test
    public void test_createReadIndexes_swapGroupSize2() {
        // arrange
        int swapGroupSize = 2;
        int[] expectedArray = {1, 0, 3, 2, 5, 4, 7, 6, 9, 8};

        // act
        int[] resultArray = OpenCLGridResult.createReadIndices(expectedArray.length, swapGroupSize);

        // assert
        assertThat(resultArray, is(equalTo(expectedArray)));
    }

    @Test
    public void test_createReadIndexes_swapGroupSize4() {
        // arrange
        int swapGroupSize = 4;
        int[] expectedArray = {3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12};

        // act
        int[] resultArray = OpenCLGridResult.createReadIndices(expectedArray.length, swapGroupSize);

        // assert
        assertThat(resultArray, is(equalTo(expectedArray)));
    }

    @Test
    public void test_createReadIndexes_swapGroupSize6() {
        // arrange
        int swapGroupSize = 8;
        int[] expectedArray = {7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8};

        // act
        int[] resultArray = OpenCLGridResult.createReadIndices(expectedArray.length, swapGroupSize);

        // assert
        assertThat(resultArray, is(equalTo(expectedArray)));
    }
}