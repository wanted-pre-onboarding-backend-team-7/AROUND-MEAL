package com.lucky.around.meal.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import org.locationtech.jts.geom.Point;

import com.lucky.around.meal.entity.enums.Category;

import lombok.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@ToString
public class Restaurant {
  @Id private String id;
  @NotNull private String restaurantName;
  @NotNull private String dosi;
  @NotNull private String sigungu;
  private String jibunDetailAddress;
  private String doroDetailAddress;

  @NotNull
  @Enumerated(value = EnumType.STRING)
  private Category category;

  private String restaurantTel;

  @Column(columnDefinition = "geometry(Point, 4326)")
  private Point location;

  private double ratingAverage;

  @Builder
  private Restaurant(
      String id,
      String restaurantName,
      String dosi,
      String sigungu,
      String jibunDetailAddress,
      String doroDetailAddress,
      Category category,
      String restaurantTel,
      Point location,
      double ratingAverage) {
    this.id = id;
    this.restaurantName = restaurantName;
    this.dosi = dosi;
    this.sigungu = sigungu;
    this.jibunDetailAddress = jibunDetailAddress;
    this.doroDetailAddress = doroDetailAddress;
    this.category = category;
    this.restaurantTel = restaurantTel;
    this.location = location;
    this.ratingAverage = ratingAverage;
  }

  public void updateRatingAverage(double ratingAverage) {
    this.ratingAverage = ratingAverage;
  }

  public String getJibunAddress() {
    return dosi + " " + sigungu + " " + jibunDetailAddress;
  }

  public String getDoroAddress() {
    return dosi + " " + sigungu + " " + doroDetailAddress;
  }
}
